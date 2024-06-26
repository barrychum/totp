#!/bin/bash

totp() {
    local key="${1// /}" digits=${2:- 6} step=${3:- 30}
    local epoch_time

    hmac_sha1() {
        local key=$1 msg=$2 i

        sha1() {
            local in=$1 msg
            local h0 h1 h2 h3 h4
            local a b c d e f
            local i j temp len plen chunk w
            local m=$((0xFFFFFFFF)) #32-bit mask

            ((h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0))

            ((len = ${#in} << 2))

            # pad80(in, c)
            #   in: hex string input
            #    c: congruency
            pad80() {
                local in=$1 c=$2

                printf -v in '%s80' "$in"
                while ((${#in} % 128 != c)); do
                    printf -v in '%s00' "$in"
                done
                printf '%s' "$in"
            }

            msg=$(pad80 "$in" 112)
            printf -v msg '%s%016X' "$msg" "$len"
            plen=${#msg}

            # 512-bit chunks = 128 hex chars
            for ((i = 0; i < plen; i += 128)); do
                chunk=${msg:i:128}
                for ((j = 0; j < 16; j++)); do
                    # convert to 32-bit int now
                    w[j]=$((16#${chunk:8*j:8}))
                done
                # extend into 80 qwords
                for ((j = 16; j <= 79; j++)); do
                    ((w[j] = w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16]))
                    # left rotate 1 with shift
                    ((w[j] = (w[j] >> 31) | (w[j] << 1)))
                    ((w[j] &= m))
                done
                ((a = h0, b = h1, c = h2, d = h3, e = h4))
                for ((j = 0; j <= 79; j++)); do
                    if ((j <= 19)); then
                        ((k = 0x5A827999, f = (b & c) | (~b & d)))
                    elif ((j <= 39)); then
                        ((k = 0x6ED9EBA1, f = b ^ c ^ d))
                    elif ((j <= 59)); then
                        ((k = 0x8F1BBCDC, f = (b & c) | (b & d) | (c & d)))
                    else
                        ((k = 0xCA62C1D6, f = b ^ c ^ d))
                    fi
                    ((f &= m))
                    ((temp = ((a << 5) | (a >> 27)) + f + e + k + w[j]))
                    ((temp &= m))
                    ((e = d, d = c, c = (b >> 2) | (b << 30), b = a, a = temp))
                done
                ((h0 += a, h1 += b, h2 += c, h3 += d, h4 += e))
                ((h0 &= m, h1 &= m, h2 &= m, h3 &= m, h4 &= m))
            done
            printf '%08x%08x%08x%08x%08x' "$h0" "$h1" "$h2" "$h3" "$h4"
        }

        # key needs to be same as sha1 blocksize
        if ((${#key} > 128)); then
            key=$(sha1 "$key")
        fi
        while ((${#key} < 128)); do
            key=${key}00
        done

        #xor key 32-bit at a time
        for ((i = 0; i < 128; i += 8)); do
            ipad=$(printf "%s%08X" "$ipad" "$((((16#${key:i:8}) ^ 0x36363636) & 0xFFFFFFFF))")
            opad=$(printf "%s%08X" "$opad" "$((((16#${key:i:8}) ^ 0x5C5C5C5C) & 0xFFFFFFFF))")
        done

        sha1 "${opad}$(sha1 "${ipad}${msg}")"
    }

    base32d() {
        toupper() { echo "$1" | tr '[:lower:]' '[:upper:]'; }
        local in=$(toupper "$1") c buffer idx bitsLeft=0 count=0 result
        local v='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567!'
        for ((i = 0; i < ${#in}; i++)); do
            c=${in:i+j:1}
            [[ $c = [[:space:]-] ]] && continue
            [[ $c = 0 ]] && c=O
            [[ $c = 1 ]] && c=L
            [[ $c = 8 ]] && c=B
            idx=${v%%${c}*}
            if [[ $idx = $v ]]; then
                printf 'Erroneous char: %s\n' "$c" >&2
                continue
            fi
            ((buffer <<= 5))
            ((val = 10#${#idx}))
            ((buffer |= val, bitsLeft += 5))
            if ((bitsLeft >= 8)); then
                ((bitsLeft -= 8))
                printf -v hex '%s%02x' "$hex" "$(((buffer >> bitsLeft) & 0xFF))"
            fi
        done
        printf '%s' "$hex"
    }

    local hkey="$(base32d "$1")"
    epoch_time=$(date +%s)
    printf -v step '%016X' "$((epoch_time / step))"
    dgst=$(hmac_sha1 "$hkey" "$step")

    offset=$((2 * 16#${dgst: -1}))
    token=$(((16#${dgst:offset:8} & 0x7fffffff) % 10 ** digits))
    printf '%06d' "$token"
}

sharedkey="test snem ofmq qqdo bukq uo2b fyax cwsd"
token_length="6"
window="30"

echo "token expires in $(($window - ($(date +%s) % $window)))"

temp="$(totp \
    "$sharedkey" \
    "$token_length" \
    "$window")"
printf "%s\n" "$temp"