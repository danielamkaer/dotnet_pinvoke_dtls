#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/ssl.h>
#include <mbedtls/error.h>

typedef int (*get_random_function)(void *argument, unsigned char *destination, size_t length);
typedef void (*log_function)(const char *message);
//typedef int

static get_random_function getRandom;
static log_function logFunction;

typedef struct context_functions {
	mbedtls_ssl_send_t *sendFunction;
	mbedtls_ssl_recv_t *receiveFunction;
	mbedtls_ssl_recv_timeout_t *receiveWithTimeoutFunction;
	mbedtls_ssl_set_timer_t *setTimerFunction;
	mbedtls_ssl_get_timer_t *getTimerFunction;
} context_functions;

typedef struct dtls_instance {
	mbedtls_ssl_context context;
	mbedtls_ssl_config config;
	context_functions contextFunctions;
} dtls_instance;

static void LogMessage(const char *message)
{
	if (logFunction != NULL)
	{
		logFunction(message);
	}
}

static void LogMessageln(const char *message)
{
	LogMessage(message);
	LogMessage("\r\n");
}

static void PrintDebug(void *context, int level, const char *fileName, int line, const char *message)
{
	char buffer[1024];

	((void) level);

	snprintf(buffer, sizeof(buffer), "mbedtls/%s:%04d [%p] : %s\r\n", context, fileName, line, message);
	LogMessage(buffer);
}

void Dtls_Initialize(get_random_function _getRandom, log_function _logFunction)
{
	getRandom = _getRandom;
	logFunction = _logFunction;
	logFunction("Initialized.\r\n");
}

static void LogBuffer(const unsigned char *buffer, size_t bufferLength)
{
	char printBuffer[2048] = {0};
	char *p = printBuffer;

	for (size_t i = 0; i < bufferLength; i++)
	{
		p += snprintf(p, sizeof(printBuffer) - (p - printBuffer), "%02x ", buffer[i]);

		if (i%16 == 15)
		{
			p += snprintf(p, sizeof(printBuffer) - (p - printBuffer), "\r\n");
		}
	}

	LogMessageln(printBuffer);
}

static int Send(void *ctx, const unsigned char *buf, size_t len)
{
	dtls_instance *instance = (dtls_instance *) ctx;

	LogMessageln("Sending buffer:");
	LogBuffer(buf, len);

	int result = instance->contextFunctions.sendFunction(ctx, buf, len);

	printf("sendFunction result = %d\r\n", result);

	return result;
}

static int Receive(void *ctx, unsigned char *buf, size_t len)
{
	dtls_instance *instance = (dtls_instance *) ctx;

	int result = instance->contextFunctions.receiveFunction(ctx, buf, len);

	printf("receiveFunction result = %d\r\n", result);

	LogMessageln("Received buffer:");
	LogBuffer(buf, len);

	return result;
}


dtls_instance *Dtls_Create(context_functions contextFunctions)
{
	LogMessageln(__FUNCTION__);

	dtls_instance *instance = malloc(sizeof(dtls_instance));

	instance->contextFunctions = contextFunctions;

	if (instance == NULL)
	{
		return NULL;
	}

	mbedtls_ssl_init(&instance->context);
	mbedtls_ssl_config_init(&instance->config);
	mbedtls_ssl_config_defaults(&instance->config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_DATAGRAM, MBEDTLS_SSL_PRESET_DEFAULT);
	mbedtls_ssl_conf_rng(&instance->config, getRandom, NULL);
	mbedtls_ssl_conf_dbg(&instance->config, PrintDebug, instance);
	mbedtls_ssl_set_bio(&instance->context, instance, Send, Receive, contextFunctions.receiveWithTimeoutFunction);
	mbedtls_ssl_set_timer_cb(&instance->context, instance, contextFunctions.setTimerFunction, contextFunctions.getTimerFunction);

	return instance;
}

void Dtls_Free(dtls_instance *instance)
{
	LogMessageln(__FUNCTION__);

	mbedtls_ssl_config_free(&instance->config);
	mbedtls_ssl_free(&instance->context);

	free(instance);
}

int Dtls_SetHostname(dtls_instance *instance, const char *hostname)
{
	return mbedtls_ssl_set_hostname(&instance->context, hostname);
}

void Dtls_SetAuthMode(dtls_instance *instance, int authMode)
{
	mbedtls_ssl_conf_authmode(&instance->config, authMode);
}

int Dtls_SetPresharedKey(dtls_instance *instance, const unsigned char *psk, size_t pskLength, const unsigned char *pskIdentity, size_t pskIdentityLength)
{
	return mbedtls_ssl_conf_psk(&instance->config, psk, pskLength, pskIdentity, pskIdentityLength);
}

int Dtls_Handshake(dtls_instance *instance)
{
	int result;

	LogMessageln(__FUNCTION__);

	result = mbedtls_ssl_setup(&instance->context, &instance->config);
	if (result != 0)
	{
		return result;
	}

	do {
		result = mbedtls_ssl_handshake(&instance->context);
	}
	while (result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE);

	char buffer[256];
	sprintf(buffer, "result=%d\r\n",result);
	LogMessage(buffer);

	return result;
}

int Dtls_Write(dtls_instance *instance, unsigned char *buffer, size_t bufferSize)
{
	return mbedtls_ssl_write(&instance->context, buffer, bufferSize);
}

int Dtls_Read(dtls_instance *instance, unsigned char *buffer, size_t bufferSize)
{
	return mbedtls_ssl_read(&instance->context, buffer, bufferSize);
}

void Dtls_GetErrorMessage(int errorCode, char *destination, size_t destinationSize)
{
	mbedtls_strerror(errorCode, destination, destinationSize);
}
