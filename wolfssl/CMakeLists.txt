add_definitions(-DBUILDING_WOLFSSL)
set(WOLFSSL_SRC
    src/crl.c
    src/internal.c
    src/keys.c
    src/ocsp.c
    src/ssl.c
    src/tls.c
    src/tls13.c
    src/wolfio.c
    wolfcrypt/src/aes.c
    wolfcrypt/src/arc4.c
    wolfcrypt/src/asm.c
    wolfcrypt/src/asn.c
    wolfcrypt/src/blake2b.c
    wolfcrypt/src/camellia.c
    wolfcrypt/src/chacha.c
    wolfcrypt/src/chacha20_poly1305.c
    wolfcrypt/src/cmac.c
    wolfcrypt/src/coding.c
    wolfcrypt/src/compress.c
    wolfcrypt/src/cpuid.c
    wolfcrypt/src/curve25519.c
    wolfcrypt/src/des3.c
    wolfcrypt/src/dh.c
    wolfcrypt/src/dsa.c
    wolfcrypt/src/ecc.c
    wolfcrypt/src/ed25519.c
    wolfcrypt/src/error.c
    wolfcrypt/src/fe_low_mem.c
    wolfcrypt/src/fe_operations.c
    wolfcrypt/src/ge_low_mem.c
    wolfcrypt/src/ge_operations.c
    wolfcrypt/src/hash.c
    wolfcrypt/src/hc128.c
    wolfcrypt/src/hmac.c
    wolfcrypt/src/idea.c
    wolfcrypt/src/integer.c
    wolfcrypt/src/logging.c
    wolfcrypt/src/md2.c
    wolfcrypt/src/md4.c
    wolfcrypt/src/md5.c
    wolfcrypt/src/memory.c
    wolfcrypt/src/pkcs7.c
    wolfcrypt/src/pkcs12.c
    wolfcrypt/src/poly1305.c
    wolfcrypt/src/pwdbased.c
    wolfcrypt/src/rabbit.c
    wolfcrypt/src/random.c
    wolfcrypt/src/ripemd.c
    wolfcrypt/src/rsa.c
    wolfcrypt/src/sha.c
    wolfcrypt/src/sha3.c
    wolfcrypt/src/sha256.c
    wolfcrypt/src/sha512.c
    wolfcrypt/src/signature.c
    wolfcrypt/src/sp_arm32.c
    wolfcrypt/src/sp_arm64.c
    wolfcrypt/src/sp_armthumb.c
    wolfcrypt/src/sp_c32.c
    wolfcrypt/src/sp_c64.c
    wolfcrypt/src/sp_cortexm.c
    wolfcrypt/src/sp_int.c
    wolfcrypt/src/sp_x86_64.c
    wolfcrypt/src/srp.c
    wolfcrypt/src/tfm.c
    wolfcrypt/src/wc_encrypt.c
    wolfcrypt/src/wc_port.c
    wolfcrypt/src/wolfevent.c
    wolfcrypt/src/wolfmath.c
    wolfcrypt/src/ed448.c
    wolfcrypt/src/fe_448.c
    wolfcrypt/src/ge_448.c
    wolfcrypt/src/curve448.c
)

if(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
    #Win平台,使用vs工程编译,暂不处理
    if((${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64") OR (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "AMD64"))
        set(WOLFSSL_SRC
            ${WOLFSSL_SRC}
            wolfcrypt/src/aes_asm.asm
        )
    endif()
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Android")
    #Android平台
    if(${CMAKE_ANDROID_ARCH_ABI} STREQUAL "x86_64")
        set(WOLFSSL_SRC
            ${WOLFSSL_SRC}
            wolfcrypt/src/aes_asm.s
            wolfcrypt/src/aes_gcm_asm.S
        )
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -maes")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -maes")
    endif()
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Darwin" 
    OR ${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD"
    OR ${CMAKE_SYSTEM_NAME} MATCHES "Linux")
	if((${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64") OR (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "amd64"))
        set(WOLFSSL_SRC
            ${WOLFSSL_SRC}
            wolfcrypt/src/aes_asm.s
            wolfcrypt/src/aes_gcm_asm.S
        )
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -maes")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -maes")
	endif()
endif()

add_library(wolfssl STATIC ${WOLFSSL_SRC})

