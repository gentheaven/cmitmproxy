#include <winsock2.h>
#include <stdio.h>

#include "proxy.h"

int win_env_init(void)
{
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;

    /* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
    wVersionRequested = MAKEWORD(2, 2);
    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        /* Tell the user that we could not find a usable */
        /* Winsock DLL.                                  */
        printf("WSAStartup failed with error: %d\n", err);
        return 1;
    }

    return 0;
}

void win_env_exit(void)
{
    WSACleanup();
}

void init_sockaddr_in(struct sockaddr_in* dest, const char* ip, int port)
{
	memset(dest, 0, sizeof(struct sockaddr_in));
	dest->sin_family = AF_INET;
	evutil_inet_pton(AF_INET, ip, &dest->sin_addr);
	dest->sin_port = htons(port);
}


void show_http_proxy(void)
{
	//print current proxy settings
	system("powershell -NoProfile -NonInteractive -Command \"Get-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'\
| Select-Object ProxyEnable, ProxyServer, ProxyOverride\"");
}

/*
 * set http proxy
 * not work: only used for command tool like curl, not affect browser
 * netsh command not work with same reason
 set http_proxy=http://127.0.0.1:8080
 set https_proxy=http://127.0.0.1:8080

check:
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" | Select-Object ProxyEnable, ProxyServer, ProxyOverride

enable proxy:
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "ProxyEnable" -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "ProxyServer" -Value "http://127.0.0.1:8080"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "ProxyOverride" -Value "localhost;127.0.0.1"

disable proxy:
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "ProxyEnable" -Value 0
*/
char gcmd[2048];
void set_http_proxy(char* proxy_ip, unsigned short  port)
{
	sprintf(gcmd, "powershell -NoProfile -NonInteractive -Command \"\
Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name \"ProxyEnable\" -Value 1; \
Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name \"ProxyServer\" -Value \"%s:%d\"; \
Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name \"ProxyOverride\" -Value \"localhost; 127.0.0.1\"  \
\"", proxy_ip, port);
	//printf("%s\n", gcmd);
	system(gcmd);
	//show_http_proxy();
}

void reset_http_proxy(void)
{
	system("powershell -NoProfile -NonInteractive -Command \"Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'\
-Name \"ProxyEnable\" -Value 0 \"");
	//show_http_proxy();
}

#define STRING_LENGTH 1024
static char log_sstr[STRING_LENGTH];
/*
 * This routine logs messages to either the log file or the syslog function.
 */
void log_message(int level, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vsnprintf(log_sstr, STRING_LENGTH, fmt, args);
    va_end(args);

    if (level <= glog_level)
        printf("%s", log_sstr);
}

int get_sockpeer_port(evutil_socket_t sockfd)
{
	struct sockaddr_in peer_addr;
	socklen_t addr_len = sizeof(peer_addr);

	if (getpeername(sockfd, (struct sockaddr*)&peer_addr, &addr_len) == 0) {
		unsigned short port = ntohs(peer_addr.sin_port);
		return port;
	}
	return 0;
}

/*
 * Add the error information to the conn structure.
 */
void indicate_http_error(struct conn_s* connptr, int number, const char* message, ...)
{
	va_list ap;
	va_start(ap, message);

	char* key, * val;
	while ((key = va_arg(ap, char*))) {
		val = va_arg(ap, char*);
		if (!strcmp(key, "detail")) {
			//only care detail info
			strncpy(connptr->detail_string, val, MAX_ERROR_MSG_LEN);
			break;
		}
	}

	connptr->error_number = number;
	vsnprintf(connptr->error_string, MAX_ERROR_MSG_LEN, message, ap);

	va_end(ap);
}

/*
 * Send a "message" to the file descriptor provided. This handles the
 * differences between the various implementations of vsnprintf. This code
 * was basically stolen from the snprintf() man page of Debian Linux
 * (although I did fix a memory leak. :)
 */
int write_message(struct conn_s* connptr, const char* fmt, ...)
{
	ssize_t n;
	size_t size = (1024 * 8);       /* start with 8 KB and go from there */
	char* buf, * tmpbuf;
	va_list ap;

	//write_message will call 
	buf = malloc(4096);

	while (1) {
		va_start(ap, fmt);
		n = vsnprintf(buf, size, fmt, ap);
		va_end(ap);

		/* If that worked, break out so we can send the buffer */
		if (n > -1 && (size_t)n < size)
			break;

		/* Else, try again with more space */
		if (n > -1)
			/* precisely what is needed (glibc2.1) */
			size = n + 1;
		else
			/* twice the old size (glibc2.0) */
			size *= 2;

		if ((tmpbuf = (char*)realloc(buf, size)) == NULL) {
			free(buf);
			return -1;
		}
		else
			buf = tmpbuf;
	}

	bufferevent_write(connptr->client_socket, buf, n);
	return 0;
}

int send_http_headers(
	struct conn_s* connptr, int code,
	const char* message, const char* extra)
{
	const char headers[] =
		"HTTP/1.%u %d %s\r\n"
		"Server: %s/%s\r\n"
		"Content-Type: text/html\r\n"
		"%s"
		"Connection: close\r\n" "\r\n";

	return (write_message(connptr, headers,
		connptr->protocol.major != 1 ? 0 : connptr->protocol.minor,
		code, message, PACKAGE, VERSION,
		extra));
}

/*
 * Display an error to the client.
 */
int send_http_error_message(struct conn_s* connptr)
{
	const char* fallback_error =
		"<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n"
		"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" "
		"\"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\n"
		"<html>\n"
		"<head><title>%d %s</title></head>\n"
		"<body>\n"
		"<h1>%s</h1>\n"
		"<p>%s</p>\n"
		"<hr />\n"
		"<p><em>Generated by %s version %s.</em></p>\n" "</body>\n"
		"</html>\n";

	const char p_auth_str[] =
		"Proxy-Authenticate: Basic realm=\""
		PACKAGE_NAME "\"\r\n";

	const char w_auth_str[] =
		"WWW-Authenticate: Basic realm=\""
		PACKAGE_NAME "\"\r\n";

	/* according to rfc7235, the 407 error must be accompanied by
	   a Proxy-Authenticate header field. */
	const char* add = connptr->error_number == 407 ? p_auth_str :
		(connptr->error_number == 401 ? w_auth_str : "");

	send_http_headers(connptr, connptr->error_number,
		connptr->error_string, add);

	char* detail = connptr->detail_string;
	return (write_message(connptr, fallback_error,
		connptr->error_number,
		connptr->error_string,
		connptr->error_string,
		detail, PACKAGE, VERSION));
}


void print_char(char* name, uint8_t* buf, int len)
{
    if (name)
        printf("%s", name);

    int i;
    for (i = 0; i < len; i++) {
        printf("%c", buf[i]);
    }
    printf("\n");
}

void print_hex(char* name, uint8_t* buf, int len)
{
    if (name)
        printf("%s", name);

    int i;
    for (i = 0; i < len; i++) {
        printf("%.2x", buf[i]);
    }
    printf("\n");
}

/*
CONNECT browser.events.data.msn.cn:443 HTTP/1.1
Host: browser.events.data.msn.cn:443
Proxy-Connection: keep-alive
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0
*/

/*
GET http://crl3.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl HTTP/1.1
Cache-Control: max-age = 5601
Proxy-Connection: Keep-Alive

If - Modified - Since: Wed, 12 Nov 2025 16 : 50 : 09 GMT
If - None - Match: "6914bac1-24033"
User - Agent : Microsoft - CryptoAPI / 10.0
Host : crl3.digicert.com
*/

/*
 * Take a host string and if there is a username/password part, strip
 * it off.
 */
static void strip_username_password(char* host)
{
	char* p;
	if ((p = strchr(host, '@')) == NULL)
		return;

	/*
	 * Move the pointer past the "@" and then copy from that point
	 * until the NUL to the beginning of the host buffer.
	 */
	p++;
	while (*p)
		*host++ = *p++;
	*host = '\0';
}

/*
 * Take a host string and if there is a port part, strip
 * it off and set proper port variable i.e. for www.host.com:8001
 */
static int strip_return_port(char* host)
{
	char* ptr1;
	char* ptr2;
	int port;

	ptr1 = strrchr(host, ':');
	if (ptr1 == NULL)
		return 0;

	/* Check for IPv6 style literals */
	ptr2 = strchr(ptr1, ']');
	if (ptr2 != NULL)
		return 0;

	*ptr1++ = '\0';
	if (sscanf(ptr1, "%d", &port) != 1)    /* one conversion required */
		return 0;
	return port;
}

/*
 * Pull the information out of the URL line.
 * This expects urls with the initial '<proto>://'
 * part stripped and hence can handle http urls,
 * (proxied) ftp:// urls and https-requests that
 * come in without the proto:// part via CONNECT.
 */
int extract_url(const char* url, int default_port, struct request_s* request)
{
	char* p;
	int port;

	/* Split the URL on the slash to separate host from path */
	p = strchr(url, '/');
	if (p != NULL) {
		int len;
		len = (int)(p - url);
		request->host = (char*)malloc(len + 1);
		memcpy(request->host, url, len);
		request->host[len] = '\0';
		request->path = _strdup(p);
	}
	else {
		request->host = _strdup(url);
		request->path = _strdup("/");
	}

	if (!request->host || !request->path)
		goto ERROR_EXIT;

	/* Remove the username/password if they're present */
	strip_username_password(request->host);

	/* Find a proper port in www.site.com:8001 URLs */
	port = strip_return_port(request->host);
	request->port = (port != 0) ? port : default_port;

	/* Remove any surrounding '[' and ']' from IPv6 literals */
	p = strrchr(request->host, ']');
	if (p && (*(request->host) == '[')) {
		memmove(request->host, request->host + 1,
			strlen(request->host) - 2);
		*p = '\0';
		p--;
		*p = '\0';
	}

	return 0;

ERROR_EXIT:
	if (request->host)
		free(request->host);
	if (request->path)
		free(request->path);
	request->host = NULL;
	request->path = NULL;
	return -1;
}

/*
 * Break the request line apart and figure out where to connect and
 * build a new request line. Finally connect to the remote server.

 CONNECT browser.events.data.msn.cn:443 HTTP/1.1

 parse result:

 method = "CONNECT"
 host = "browser.events.data.msn.cn"
 port = 443
 path = "/"
 connptr->protocol.major = 1;
 connptr->protocol.minor = 1;

 return 1 if failed
 return 0 if OK
 */
int parse_connect_request(char* buf, int len, struct child* pchild)
{
	char* url;
	int ret;
	size_t request_len;

	request_len = len + 1;
	struct request_s* request = &pchild->req;

	memset(request, 0, sizeof(struct request_s));
	request->method = (char*)malloc(request_len);
	url = (char*)malloc(request_len);
	request->protocol = (char*)malloc(request_len);

	if (!request->method || !url || !request->protocol) {
		goto fail;
	}

	/* zero-terminate the strings so they don't contain junk in error page */
	request->method[0] = url[0] = request->protocol[0] = 0;

	ret = sscanf(buf, "%[^ ] %[^ ] %[^ ]",
		request->method, url, request->protocol);

	struct conn_s* connptr = &pchild->conn;
	if (ret == 2 && !strcasecmp(request->method, "GET")) {
		request->protocol[0] = 0;

		/* Indicate that this is a HTTP/0.9 GET request */
		connptr->protocol.major = 0;
		connptr->protocol.minor = 9;
	} else if (ret == 3 && !strncasecmp(request->protocol, "HTTP/", 5)) {
		/*
		 * Break apart the protocol and update the connection
		 * structure.
		 */
		ret = sscanf(request->protocol + 5, "%u.%u",
			&connptr->protocol.major,
			&connptr->protocol.minor);

		/*
		 * If the conversion doesn't succeed, drop down below and
		 * send the error to the user.
		 */
		if (ret != 2)
			goto BAD_REQUEST_ERROR;
	} else {
	BAD_REQUEST_ERROR:
		log_message(LOG_ERR,
			"process_request: Bad Request on file descriptor %d\n",
			connptr->client_socket);
		indicate_http_error(connptr, 400, "Bad Request",
			"detail", "Request has an invalid format",
			"url", url, NULL);
		goto fail;
	}

	if (strncasecmp(url, "http://", 7) == 0) {
		char* skipped_type = strstr(url, "//") + 2;

		if (extract_url(skipped_type, HTTP_PORT, request) < 0) {
			indicate_http_error(connptr, 400, "Bad Request",
				"detail", "Could not parse URL",
				"url", url, NULL);
			goto fail;
		}
	} else if (strcmp(request->method, "CONNECT") == 0) {
		if (extract_url(url, HTTP_PORT_SSL, request) < 0) {
			indicate_http_error(connptr, 400, "Bad Request",
				"detail", "Could not parse URL",
				"url", url, NULL);
			goto fail;
		}
		//connptr->connect_method = TRUE;
	} else {
		indicate_http_error(connptr, 501, "Not Implemented",
			"detail",
			"Unknown method or unsupported protocol.",
			"url", url, NULL);
		log_message(LOG_INFO, "Unknown method (%s) or protocol (%s)",
			request->method, url);
		goto fail;
	}

	free(url);
	return 0;

fail:
	free(url);
	free_request_struct(request);
	return 1;
}

/*
 * Free all the memory allocated in a request.
 */
void free_request_struct(struct request_s* request)
{
	if (!request)
		return;
	if (request->method)
		free(request->method);
	if (request->protocol)
		free(request->protocol);

	if (request->host)
		free(request->host);
	if (request->path)
		free(request->path);
	memset(request, 0, sizeof(struct request_s));
}

