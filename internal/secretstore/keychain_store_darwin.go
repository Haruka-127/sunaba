//go:build darwin && cgo

package secretstore

/*
#cgo CFLAGS: -Wno-deprecated-declarations
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/SecBase.h>
#include <Security/SecKeychain.h>
#include <Security/SecKeychainItem.h>
#include <stdlib.h>
#include <string.h>

static OSStatus sunaba_open_keychain(const char *keychain_path, SecKeychainRef *keychain) {
	return SecKeychainOpen(keychain_path, keychain);
}

static OSStatus sunaba_find_generic_password(
	SecKeychainRef keychain,
	const char *service,
	UInt32 service_length,
	const char *account,
	UInt32 account_length,
	UInt32 *secret_length,
	void **secret,
	SecKeychainItemRef *item
) {
	return SecKeychainFindGenericPassword(
		keychain,
		service_length,
		service,
		account_length,
		account,
		secret_length,
		secret,
		item
	);
}

typedef struct {
	OSStatus status;
	void *secret;
	UInt32 secret_length;
} SunabaSecretResult;

static SunabaSecretResult sunaba_copy_generic_password(
	const char *keychain_path,
	const char *service,
	UInt32 service_length,
	const char *account,
	UInt32 account_length,
	UInt32 maximum_length
) {
	SunabaSecretResult result = { errSecSuccess, NULL, 0 };
	SecKeychainRef keychain = NULL;
	void *secret = NULL;
	UInt32 secret_length = 0;
	result.status = sunaba_open_keychain(keychain_path, &keychain);
	if (result.status != errSecSuccess) {
		return result;
	}

	result.status = sunaba_find_generic_password(
		keychain,
		service,
		service_length,
		account,
		account_length,
		&secret_length,
		&secret,
		NULL
	);
	if (result.status == errSecSuccess && secret_length > maximum_length) {
		result.status = errSecDataTooLarge;
	}
	if (result.status == errSecSuccess) {
		result.secret = malloc(secret_length);
		if (result.secret == NULL) {
			result.status = errSecAllocate;
		} else {
			memcpy(result.secret, secret, secret_length);
			result.secret_length = secret_length;
		}
	}

	if (secret != NULL) {
		SecKeychainItemFreeContent(NULL, secret);
	}
	CFRelease(keychain);
	return result;
}

static void sunaba_clear_and_free(void *secret, UInt32 secret_length) {
	if (secret == NULL) {
		return;
	}
	volatile unsigned char *cursor = (volatile unsigned char *)secret;
	while (secret_length-- > 0) {
		*cursor++ = 0;
	}
	free(secret);
}

static OSStatus sunaba_store_generic_password(
	const char *keychain_path,
	const char *service,
	UInt32 service_length,
	const char *account,
	UInt32 account_length,
	const void *secret,
	UInt32 secret_length
) {
	SecKeychainRef keychain = NULL;
	SecKeychainItemRef item = NULL;
	OSStatus status = sunaba_open_keychain(keychain_path, &keychain);
	if (status != errSecSuccess) {
		return status;
	}

	status = sunaba_find_generic_password(
		keychain,
		service,
		service_length,
		account,
		account_length,
		NULL,
		NULL,
		&item
	);
	if (status == errSecSuccess) {
		status = SecKeychainItemModifyAttributesAndData(item, NULL, secret_length, secret);
	} else if (status == errSecItemNotFound) {
		status = SecKeychainAddGenericPassword(
			keychain,
			service_length,
			service,
			account_length,
			account,
			secret_length,
			secret,
			NULL
		);
	}

	if (item != NULL) {
		CFRelease(item);
	}
	CFRelease(keychain);
	return status;
}

static OSStatus sunaba_generic_password_exists(
	const char *keychain_path,
	const char *service,
	UInt32 service_length,
	const char *account,
	UInt32 account_length
) {
	SecKeychainRef keychain = NULL;
	SecKeychainItemRef item = NULL;
	OSStatus status = sunaba_open_keychain(keychain_path, &keychain);
	if (status != errSecSuccess) {
		return status;
	}
	status = sunaba_find_generic_password(
		keychain,
		service,
		service_length,
		account,
		account_length,
		NULL,
		NULL,
		&item
	);
	if (item != NULL) {
		CFRelease(item);
	}
	CFRelease(keychain);
	return status;
}

static OSStatus sunaba_delete_generic_password(
	const char *keychain_path,
	const char *service,
	UInt32 service_length,
	const char *account,
	UInt32 account_length
) {
	SecKeychainRef keychain = NULL;
	SecKeychainItemRef item = NULL;
	OSStatus status = sunaba_open_keychain(keychain_path, &keychain);
	if (status != errSecSuccess) {
		return status;
	}
	status = sunaba_find_generic_password(
		keychain,
		service,
		service_length,
		account,
		account_length,
		NULL,
		NULL,
		&item
	);
	if (status == errSecSuccess) {
		status = SecKeychainItemDelete(item);
	}
	if (item != NULL) {
		CFRelease(item);
	}
	CFRelease(keychain);
	return status;
}
*/
import "C"

import (
	"fmt"
	"runtime"
	"unsafe"
)

func platformLoadGenericPassword(keychain, service, account string) ([]byte, error) {
	keychainPath, serviceName, accountName, release := keychainStrings(keychain, service, account)
	defer release()
	result := C.sunaba_copy_generic_password(
		keychainPath,
		serviceName,
		C.UInt32(len(service)),
		accountName,
		C.UInt32(len(account)),
		C.UInt32(maximumSecretBytes),
	)
	if result.status != C.errSecSuccess {
		return nil, keychainStatusError(result.status)
	}
	defer C.sunaba_clear_and_free(result.secret, result.secret_length)
	if result.secret_length == 0 {
		return nil, fmt.Errorf("Security.framework returned an empty Keychain secret")
	}
	return C.GoBytes(result.secret, C.int(result.secret_length)), nil
}

func platformStoreGenericPassword(keychain, service, account string, secret []byte) error {
	if len(secret) == 0 {
		return fmt.Errorf("native Keychain secret is empty")
	}
	keychainPath, serviceName, accountName, release := keychainStrings(keychain, service, account)
	defer release()

	status := C.sunaba_store_generic_password(
		keychainPath,
		serviceName,
		C.UInt32(len(service)),
		accountName,
		C.UInt32(len(account)),
		unsafe.Pointer(&secret[0]),
		C.UInt32(len(secret)),
	)
	runtime.KeepAlive(secret)
	if status != C.errSecSuccess {
		return keychainStatusError(status)
	}
	return nil
}

func platformGenericPasswordExists(keychain, service, account string) error {
	keychainPath, serviceName, accountName, release := keychainStrings(keychain, service, account)
	defer release()
	status := C.sunaba_generic_password_exists(keychainPath, serviceName, C.UInt32(len(service)), accountName, C.UInt32(len(account)))
	if status != C.errSecSuccess {
		return keychainStatusError(status)
	}
	return nil
}

func platformDeleteGenericPassword(keychain, service, account string) error {
	keychainPath, serviceName, accountName, release := keychainStrings(keychain, service, account)
	defer release()
	status := C.sunaba_delete_generic_password(keychainPath, serviceName, C.UInt32(len(service)), accountName, C.UInt32(len(account)))
	if status != C.errSecSuccess {
		return keychainStatusError(status)
	}
	return nil
}

func keychainStrings(keychain, service, account string) (*C.char, *C.char, *C.char, func()) {
	keychainPath := C.CString(keychain)
	serviceName := C.CString(service)
	accountName := C.CString(account)
	return keychainPath, serviceName, accountName, func() {
		C.free(unsafe.Pointer(keychainPath))
		C.free(unsafe.Pointer(serviceName))
		C.free(unsafe.Pointer(accountName))
	}
}

func keychainStatusError(status C.OSStatus) error {
	return fmt.Errorf("Security.framework returned OSStatus %d", int32(status))
}
