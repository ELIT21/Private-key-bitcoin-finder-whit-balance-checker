import os
import hashlib
import base58
import ecdsa
from Crypto.Hash import SHA256, RIPEMD160
import bech32
from bech32 import convertbits
import time
import aiohttp
import asyncio
import colorama
from colorama import Fore, Style

def generate_bitcoin_address():
    private_key = os.urandom(32)
    fullkey = '80' + private_key.hex()
    sha256a = SHA256.new(bytes.fromhex(fullkey)).hexdigest()
    sha256b = SHA256.new(bytes.fromhex(sha256a)).hexdigest()
    WIF = base58.b58encode(bytes.fromhex(fullkey + sha256b[:8]))

    compressed_fullkey = '80' + private_key.hex() + '01'
    sha256a_compressed = SHA256.new(bytes.fromhex(compressed_fullkey)).hexdigest()
    sha256b_compressed = SHA256.new(bytes.fromhex(sha256a_compressed)).hexdigest()
    compressed_WIF = base58.b58encode(bytes.fromhex(compressed_fullkey + sha256b_compressed[:8]))

    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()
    public_key = '04' + x.to_bytes(32, 'big').hex() + y.to_bytes(32, 'big').hex()

    compressed_public_key = '02' if y % 2 == 0 else '03'
    compressed_public_key += x.to_bytes(32, 'big').hex()

    hash160 = RIPEMD160.new()
    hash160.update(SHA256.new(bytes.fromhex(public_key)).digest())
    public_key_hash = '00' + hash160.hexdigest()
    checksum = SHA256.new(SHA256.new(bytes.fromhex(public_key_hash)).digest()).hexdigest()[:8]
    p2pkh_address = base58.b58encode(bytes.fromhex(public_key_hash + checksum))

    hash160 = RIPEMD160.new()
    hash160.update(SHA256.new(bytes.fromhex(compressed_public_key)).digest())
    public_key_hash = '00' + hash160.hexdigest()
    checksum = SHA256.new(SHA256.new(bytes.fromhex(public_key_hash)).digest()).hexdigest()[:8]
    compressed_p2pkh_address = base58.b58encode(bytes.fromhex(public_key_hash + checksum))

    redeem_script = '0014' + hash160.digest().hex()
    hash160_redeem_script = RIPEMD160.new()
    hash160_redeem_script.update(SHA256.new(bytes.fromhex(redeem_script)).digest())
    script_hash = '05' + hash160_redeem_script.hexdigest()
    checksum = SHA256.new(SHA256.new(bytes.fromhex(script_hash)).digest()).hexdigest()[:8]
    p2sh_address = base58.b58encode(bytes.fromhex(script_hash + checksum))

    sha256_compressed = SHA256.new(bytes.fromhex(compressed_public_key)).digest()
    ripemd160_digest = hashlib.new("ripemd160", sha256_compressed).digest()
    words = convertbits(ripemd160_digest, 8, 5)
    bech32_address = bech32.bech32_encode("bc", [0] + words)

    return {
        'private_key': private_key.hex(),
        'WIF': WIF.decode('utf-8'),
        'compressed_WIF': compressed_WIF.decode('utf-8'),
        'p2pkh_address': p2pkh_address.decode('utf-8'),
        'compressed_p2pkh_address': compressed_p2pkh_address.decode('utf-8'),
        'p2sh_address': p2sh_address.decode('utf-8'),
        'bech32_address': bech32_address
    }

async def check_balance_with_retry(session, address):
    api_url = f'https://bitcoin.atomicwallet.io/api/v2/address/{address}'

    while True:
        try:
            async with session.get(api_url, timeout=5000) as response:
                if response.status == 200:
                    data = await response.json()
                    return str(data.get('balance', 0))
                else:
                    print(f"{Fore.RED}Error checking balance for address {address}. Status code: {response.status}{Style.RESET_ALL}")
        except aiohttp.ClientError as e:
            print(f"{Fore.RED}Network error: {e}. Retrying...{Style.RESET_ALL}")
        except asyncio.TimeoutError:
            print(f"{Fore.RED}TimeoutError: Request timed out. Retrying...{Style.RESET_ALL}")

        await asyncio.sleep(1)

def write_to_file(filename, content):
    with open(filename, 'a') as file:
        file.write(content + '\n')

async def process_address(session, address_info, address_type, data_storage=None):
    balance = await check_balance_with_retry(session, address_info[address_type])
    print(f"{Fore.BLUE}{address_type.capitalize()} Address: {Fore.YELLOW}{address_info[address_type]}, "
          f"{Fore.GREEN}Balance: {Fore.RED if int(balance) == 0 else Fore.GREEN}{balance}{Style.RESET_ALL}")

    if int(balance) > 0:
        wif_key = address_info['compressed_WIF'] if 'compressed' in address_type else address_info['WIF']
        compressed_wif_key = address_info['compressed_WIF']

        data_storage[address_type]['addresses'].append(address_info['p2pkh_address'])
        data_storage[address_type]['wif_keys'].append(wif_key)
        data_storage[address_type]['compressed_wif_keys'].append(compressed_wif_key)
        data_storage[address_type]['hex_private_keys'].append(address_info['private_key'])

        write_to_file('find.txt', f"{Fore.GREEN}======================= BALANCE FOUND! ======================={Style.RESET_ALL}\n")
        write_to_file('find.txt', f"{Fore.GREEN}Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
        write_to_file('find.txt', f"{Fore.BLUE}{address_type.capitalize()} Address: {Fore.YELLOW}{address_info['p2pkh_address']}{Style.RESET_ALL}")
        write_to_file('find.txt', f"{Fore.BLUE}Private Key (Hex): {Fore.YELLOW}{address_info['private_key']}{Style.RESET_ALL}")
        write_to_file('find.txt', f"{Fore.BLUE}Private Key (WIF): {Fore.YELLOW}{wif_key}{Style.RESET_ALL}")
        write_to_file('find.txt', f"{Fore.BLUE}Private Key (Compressed WIF): {Fore.YELLOW}{compressed_wif_key}{Style.RESET_ALL}")
        write_to_file('find.txt', f"{Fore.BLUE}Balance: {Fore.GREEN}{balance}{Style.RESET_ALL}")
        write_to_file('find.txt', f"{Fore.BLUE}Uncompressed P2PKH Address: {Fore.YELLOW}{address_info['uncompressed_p2pkh_address']}{Style.RESET_ALL}")
        write_to_file('find.txt', f"{Fore.BLUE}Compressed P2PKH Address: {Fore.YELLOW}{address_info['compressed_p2pkh_address']}{Style.RESET_ALL}")
        write_to_file('find.txt', f"{Fore.BLUE}P2SH Address: {Fore.YELLOW}{address_info['p2sh_address']}{Style.RESET_ALL}")
        write_to_file('find.txt', f"{Fore.BLUE}Bech32 Address: {Fore.YELLOW}{address_info['bech32_address']}{Style.RESET_ALL}")
        write_to_file('find.txt', f"{Fore.GREEN}=============================================================={Style.RESET_ALL}\n")

async def main():
    async with aiohttp.ClientSession() as session:
        counter = 0
        data_storage = {
            'p2pkh_address': {
                'addresses': [],
                'wif_keys': [],
                'compressed_wif_keys': [],
                'hex_private_keys': []
            },
            'compressed_p2pkh_address': {
                'addresses': [],
                'wif_keys': [],
                'compressed_wif_keys': [],
                'hex_private_keys': []
            },
            'p2sh_address': {
                'addresses': [],
                'wif_keys': [],
                'compressed_wif_keys': [],
                'hex_private_keys': []
            },
            'bech32_address': {
                'addresses': [],
                'wif_keys': [],
                'compressed_wif_keys': [],
                'hex_private_keys': []
            }
        }

        while True:
            private_keys_info = [generate_bitcoin_address() for _ in range(25000)]

            await asyncio.gather(
                *[process_address(session, address_info, 'p2pkh_address', data_storage=data_storage) for address_info in private_keys_info],
                *[process_address(session, address_info, 'compressed_p2pkh_address', data_storage=data_storage) for address_info in private_keys_info],
                *[process_address(session, address_info, 'p2sh_address', data_storage=data_storage) for address_info in private_keys_info],
                *[process_address(session, address_info, 'bech32_address', data_storage=data_storage) for address_info in private_keys_info]
            )

            counter += 100000
            print(f"{Fore.BLUE}Total iterations: {counter}{Style.RESET_ALL}")

            if any(map(lambda balance: int(balance) > 0, data_storage['p2pkh_address']['addresses'])):
                pass

            data_storage = {
                'p2pkh_address': {
                    'addresses': [],
                    'wif_keys': [],
                    'compressed_wif_keys': [],
                    'hex_private_keys': []
                },
                'compressed_p2pkh_address': {
                    'addresses': [],
                    'wif_keys': [],
                    'compressed_wif_keys': [],
                    'hex_private_keys': []
                },
                'p2sh_address': {
                    'addresses': [],
                    'wif_keys': [],
                    'compressed_wif_keys': [],
                    'hex_private_keys': []
                },
                'bech32_address': {
                    'addresses': [],
                    'wif_keys': [],
                    'compressed_wif_keys': [],
                    'hex_private_keys': []
                }
            }

            await asyncio.sleep(1)

if __name__ == "__main__":
    colorama.init()
    asyncio.run(main())