import requests
from radix_engine_toolkit import *
from typing import Tuple
import secrets
import json
import time
from scipy.optimize import fsolve

NETWORK_ID: int = 0x01
private_key_list = #use your own private key here
ORACLE_ADDRESS = "component_rdx1czc98y36sjzn3rzf60rjdc2ks33zlpn8lkv5nc7z30amhxzslccyvs"
REWARD_ACCOUNT_ADDRESS = "account_rdx12xl2meqtelz47mwp3nzd72jkwyallg5yxr9hkc75ac4qztsxulfpew"
PROXY_ADDRESS = "component_rdx1cqecl844an5n8w7dpelwr6mxrgad2kzj57nl5064q64wxwyxaxxpuk"
DAO_ADDRESS = "component_rdx1cpj9kwxx4dqxu797dhkvtskhlxvxajl6ztkktxl9atqdtcqefk9dnh"
POOL_ADDRESS = "pool_rdx1c4jj8lklg7edacflhk0tl202dzgawkujly4kqf0jfehyqd8watxw0r"
STAB_ADDRESS = "resource_rdx1t40lchq8k38eu4ztgve5svdpt0uxqmkvpy4a2ghnjcxjtdxttj9uam"
STAB_COMPONENT = "component_rdx1cq70cjajtvllgk9z9wm9l8v6w8hsgtlw530cdgpraxprn4yevg89kf"
XRD_ADDRESS = "resource_rdx1tknxxxxxxxxxradxrdxxxxxxxxx009923554798xxxxxxxxxradxrd"
LOAN_RECEIPT_ADDRESS = "resource_rdx1ngqggm445297u03dka8r86acvvf2vv5a74y0t0xjdpx5d7thactfa0"
SWAP_COMPONENT = "component_rdx1cz9nke03hd9wgvkck0dw2tdcu4ex588e0c283lmu5f2are8e6h9rk2"
PRICE_TARGET_FRACTION = 0.948
FEE = 0.001


if NETWORK_ID == 0x02:
    url = #morpher price request for stokenet back-end endpoint
else:
    url = #morpher price request for mainnet back-end endpoint

import requests

class GatewayApiClient:
    BASE_URL = "https://mainnet.radixdlt.com"

    @staticmethod
    def current_epoch() -> int:
        try:
            response = requests.post(f"{GatewayApiClient.BASE_URL}/status/gateway-status")
            response.raise_for_status()  # Raise an error for bad status codes
            data = response.json()
            return data['ledger_state']['epoch']
        except Exception as e:
            print(f"Error fetching current epoch: {e}")
            raise

    @staticmethod
    def submit_transaction(transaction: NotarizedTransaction) -> dict:
        try:
            transaction_hex = transaction.compile().hex()
            payload = {"notarized_transaction_hex": transaction_hex}
            response = requests.post(f"{GatewayApiClient.BASE_URL}/transaction/submit", json=payload)
            response.raise_for_status()  # Raise an error for bad status codes
            return response.json()
        except Exception as e:
            print(f"Error submitting transaction: {e}")
            raise

    @staticmethod
    def get_entity_details(proxy_address: str, pool_address: str) -> dict:
        try:
            payload = {
                "addresses": [
                    POOL_ADDRESS, PROXY_ADDRESS
                ],
                "aggregation_level": "Vault"
            }
            response = requests.post(f"{GatewayApiClient.BASE_URL}/state/entity/details", json=payload)
            response.raise_for_status()  # Raise an error for bad status codes
            return response.json()  # Handle the returned data as needed
        except Exception as e:
            print(f"Error fetching entity details: {e}")
            raise
    @staticmethod
    def preview_force_liquidation() -> dict:
        try:
            current_epoch = GatewayApiClient.current_epoch()
            start_epoch_inclusive = current_epoch
            end_epoch_exclusive = current_epoch + 2

            manifest = f"""
            CALL_METHOD
                Address("{STAB_COMPONENT}")
                "free_stab"
                Decimal("100000000");

            TAKE_ALL_FROM_WORKTOP
                Address("{STAB_ADDRESS}")
                Bucket("stab");

            CALL_METHOD
                Address("{PROXY_ADDRESS}")
                "force_liquidate"
                Address("{XRD_ADDRESS}")
                Bucket("stab");

            CALL_METHOD
                Address("{REWARD_ACCOUNT_ADDRESS}")
                "deposit_batch"
                Expression("ENTIRE_WORKTOP");
            """

            # JSON payload
            payload = {
                "manifest": manifest,
                "start_epoch_inclusive": start_epoch_inclusive,
                "end_epoch_exclusive": end_epoch_exclusive,
                "tip_percentage": 0,
                "nonce": 1,
                "signer_public_keys": [
                    {
                        "key_type": "EcdsaSecp256k1",
                        "key_hex": "0305684de356f5126befda977935827f6f74ca3b7865cd8516ca72ef7afc8c0e06"
                    }
                ],
                "flags": {
                    "use_free_credit": True,
                    "assume_all_signature_proofs": True,
                    "skip_epoch_check": True,
                    "disable_auth_checks": True
                }
            }

            # Send the POST request
            response = requests.post(f"{GatewayApiClient.BASE_URL}/transaction/preview", json=payload)
            response.raise_for_status()  # Raise an error for bad status codes
            response_data = response.json()

            return response_data
        except Exception as e:
            print(f"Error previewing transaction: {e}")
            raise

    def preview_liquidation() -> dict:
        try:
            current_epoch = GatewayApiClient.current_epoch()
            start_epoch_inclusive = current_epoch
            end_epoch_exclusive = current_epoch + 2

            manifest = f"""
            CALL_METHOD
                Address("{STAB_COMPONENT}")
                "free_stab"
                Decimal("100000000");

            TAKE_ALL_FROM_WORKTOP
                Address("{STAB_ADDRESS}")
                Bucket("stab");

            CALL_METHOD
                Address("{PROXY_ADDRESS}")
                "liquidate_position_without_marker"
                Bucket("stab")
                true
                0i64
                NonFungibleLocalId("#0#");

            CALL_METHOD
                Address("{REWARD_ACCOUNT_ADDRESS}")
                "deposit_batch"
                Expression("ENTIRE_WORKTOP");
            """

            # JSON payload
            payload = {
                "manifest": manifest,
                "start_epoch_inclusive": start_epoch_inclusive,
                "end_epoch_exclusive": end_epoch_exclusive,
                "tip_percentage": 0,
                "nonce": 1,
                "signer_public_keys": [
                    {
                        "key_type": "EcdsaSecp256k1",
                        "key_hex": "0305684de356f5126befda977935827f6f74ca3b7865cd8516ca72ef7afc8c0e06"
                    }
                ],
                "flags": {
                    "use_free_credit": True,
                    "assume_all_signature_proofs": True,
                    "skip_epoch_check": True,
                    "disable_auth_checks": True
                }
            }

            # Send the POST request
            response = requests.post(f"{GatewayApiClient.BASE_URL}/transaction/preview", json=payload)
            response.raise_for_status()  # Raise an error for bad status codes
            response_data = response.json()

            return response_data
        except Exception as e:
            print(f"Error previewing transaction: {e}")
            raise
    def preview_mark() -> dict:
        try:
            current_epoch = GatewayApiClient.current_epoch()
            start_epoch_inclusive = current_epoch
            end_epoch_exclusive = current_epoch + 2

            manifest = f"""
            CALL_METHOD
                Address("{PROXY_ADDRESS}")
                "mark_for_liquidation"
                Address("{XRD_ADDRESS}")
                ;

            CALL_METHOD
                Address("{REWARD_ACCOUNT_ADDRESS}")
                "deposit_batch"
                Expression("ENTIRE_WORKTOP");
            """

            # JSON payload
            payload = {
                "manifest": manifest,
                "start_epoch_inclusive": start_epoch_inclusive,
                "end_epoch_exclusive": end_epoch_exclusive,
                "tip_percentage": 0,
                "nonce": 1,
                "signer_public_keys": [
                    {
                        "key_type": "EcdsaSecp256k1",
                        "key_hex": "0305684de356f5126befda977935827f6f74ca3b7865cd8516ca72ef7afc8c0e06"
                    }
                ],
                "flags": {
                    "use_free_credit": True,
                    "assume_all_signature_proofs": True,
                    "skip_epoch_check": True,
                    "disable_auth_checks": True
                }
            }

            # Send the POST request
            response = requests.post(f"{GatewayApiClient.BASE_URL}/transaction/preview", json=payload)
            response.raise_for_status()  # Raise an error for bad status codes
            response_data = response.json()

            return response_data
        except Exception as e:
            print(f"Error previewing transaction: {e}")
            raise

def transpose_price_data(data):
    price_info = data['data'][0]
    signature = data['signature']
    return (f"{price_info['marketId']}-{price_info['price']}-{price_info['nonce']}-{price_info['createdAt']}", signature, price_info['price'])

def get_xrd_price():
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()

        # Transpose the data
        transposed_data, signature, xrd_price = transpose_price_data(data)
        print(f"Transposed data: {transposed_data}")
        return transposed_data, signature, xrd_price
    else:
        raise ValueError(f"Request failed with status code {response.status_code}")

def account_from_keys(network_id: int) -> Tuple[PrivateKey, PublicKey, Address]:
    private_key_bytes = bytes(private_key_list)
    private_key: PrivateKey = PrivateKey.new_secp256k1(private_key_bytes)
    public_key: PublicKey = private_key.public_key()
    account: Address = derive_virtual_account_address_from_public_key(
        public_key, network_id
    )
    return (private_key, public_key, account)

def random_nonce() -> int:
    """
    Generates a random secure random number between 0 and 0xFFFFFFFF (u32::MAX)
    """
    return secrets.randbelow(0xFFFFFFFF)

def get_pool_amounts(data):
    index = 1
    if data['items'][0]['address'] == POOL_ADDRESS:
        index = 0

    items = data['items'][index]['fungible_resources']['items']
    vault_1_amount = items[0]['vaults']['items'][0]['amount']
    vault_2_amount = items[1]['vaults']['items'][0]['amount']
    vault_1_address = items[0]['resource_address']
    vault_2_address = items[1]['resource_address']

    if vault_1_address == STAB_ADDRESS:
        stab_amount = vault_1_amount
        xrd_amount = vault_2_amount
    else:
        stab_amount = vault_2_amount
        xrd_amount = vault_1_amount

    return float(stab_amount), float(xrd_amount)

def get_stab_internal_price(data):
    index = 1
    if data['items'][0]['address'] == PROXY_ADDRESS:
        index = 0

    internal_price = data['items'][index]['details']['state']['fields'][15]['fields'][4]['value']

    return float(internal_price)

def calculate_output_amount(input_amount, input_reserves, output_reserves, fee):
    return (input_amount * output_reserves * (1 - fee)) / (input_reserves + input_amount * (1 - fee))

def price_after_swap(input_amount, input_reserves, output_reserves, fee):
    output_amount = calculate_output_amount(input_amount, input_reserves, output_reserves, fee)

    new_input_reserves = input_reserves + input_amount * (1 - fee)
    new_output_reserves = output_reserves - output_amount

    return new_input_reserves / new_output_reserves

def find_required_input_amount(target_price, input_reserves, output_reserves, fee):
    def equation_to_solve(input_amount):
        return price_after_swap(input_amount, input_reserves, output_reserves, fee) - target_price

    initial_guess = 1.0
    input_amount_solution = fsolve(equation_to_solve, initial_guess)

    return input_amount_solution[0]

def extract_resource_amounts(response_data):
    resource_stab_amount = None
    resource_xrd_amount = None

    for resource_change in response_data.get("resource_changes", []):
        for change in resource_change.get("resource_changes", []):
            resource_address = change.get("resource_address")
            amount = change.get("amount")

            if resource_address == STAB_ADDRESS:
                resource_stab_amount = amount
            elif resource_address == XRD_ADDRESS:
                resource_xrd_amount = amount

    used_stab = 100000000 - float(resource_stab_amount)

    return used_stab, float(resource_xrd_amount)

def arbitrage(xrd_price, account_address, private_key, public_key):
    print("we traging")
    fee = FEE
    stab_state = GatewayApiClient.get_entity_details(PROXY_ADDRESS, POOL_ADDRESS)
    output_reserves, input_reserves = get_pool_amounts(stab_state)
    stab_internal_price = get_stab_internal_price(stab_state)

    target_price = PRICE_TARGET_FRACTION * stab_internal_price / xrd_price

    required_input_amount = find_required_input_amount(target_price, input_reserves, output_reserves, fee)
    stab_for_one_liq, xrd_rewarded = extract_resource_amounts(GatewayApiClient.preview_force_liquidation())

    print(required_input_amount, xrd_rewarded)

    if required_input_amount > 0:
        if required_input_amount > xrd_rewarded:
            print("lets go again")
            fraction_to_liquidate = 1
            go_again = True
        else:
            print("i've had enough'")
            fraction_to_liquidate = required_input_amount / xrd_rewarded
            go_again = False

        stab_to_use = stab_for_one_liq * fraction_to_liquidate + 0.001

        manifest_string: str = f"""
            CALL_METHOD
                Address("{account_address.as_str()}")
                "lock_fee"
                Decimal("10")
            ;
            CALL_METHOD
                Address("{PROXY_ADDRESS}")
                "flash_borrow"
                Decimal("{stab_to_use}");

            TAKE_ALL_FROM_WORKTOP
                Address("{STAB_ADDRESS}")
                Bucket("stab");

            CALL_METHOD
                Address("{PROXY_ADDRESS}")
                "force_liquidate"
                Address("{XRD_ADDRESS}")
                Bucket("stab");

            TAKE_ALL_FROM_WORKTOP
                Address("{XRD_ADDRESS}")
                Bucket("xrd");

            CALL_METHOD
                Address("{SWAP_COMPONENT}")
                "swap"
                Bucket("xrd");

            TAKE_ALL_FROM_WORKTOP
                Address("{STAB_ADDRESS}")
                Bucket("stab_bucket");

            TAKE_ALL_FROM_WORKTOP
                Address("{LOAN_RECEIPT_ADDRESS}")
                Bucket("receipt_bucket");

            CALL_METHOD
                Address("{PROXY_ADDRESS}")
                "flash_pay_back"
                Bucket("receipt_bucket")
                Bucket("stab_bucket");

            CALL_METHOD
                Address("{REWARD_ACCOUNT_ADDRESS}")
                "try_deposit_batch_or_abort"
                Expression("ENTIRE_WORKTOP")
                Enum<1u8>(
                    Enum<0u8>(
                        NonFungibleGlobalId("resource_rdx1nfxxxxxxxxxxsecpsgxxxxxxxxx004638826440xxxxxxxxxsecpsg:[2c4f19a2711fa4a8d242a99ff8474d10b572c277a05aed392e69a882cf]")
                    )
                )
            ;
            """
        manifest: TransactionManifest = TransactionManifest(
            Instructions.from_string(manifest_string, NETWORK_ID),
            []
        )
        manifest.statically_validate()

        current_epoch: int = GatewayApiClient.current_epoch()
        transaction: NotarizedTransaction = (
            TransactionBuilder()
            .header(
                TransactionHeader(
                    NETWORK_ID,
                    current_epoch,
                    current_epoch + 10,
                    random_nonce(),
                    public_key,
                    True,
                    0,
                )
            )
            .manifest(manifest)
            .message(Message.NONE())
            .notarize_with_private_key(private_key)
        )

        transaction_id: TransactionHash = transaction.intent_hash()

        response = GatewayApiClient.submit_transaction(transaction)

        if go_again:
            time.sleep(8)
            arbitrage(xrd_price, account_address, private_key, public_key)

        return {
            "Transaction ID": transaction_id.as_str(),
            "Response": response
        }

def do_markings(account_address, private_key, public_key):
    print("startmarks")
    mark_result = GatewayApiClient.preview_mark()['receipt']['status']
    if mark_result == "Succeeded":
        manifest_string: str = f"""
            CALL_METHOD
                Address("{account_address.as_str()}")
                "lock_fee"
                Decimal("10")
            ;

            CALL_METHOD
                Address("{PROXY_ADDRESS}")
                "mark_for_liquidation"
                Address("{XRD_ADDRESS}")
            ;

            CALL_METHOD
                Address("{account_address.as_str()}")
                "deposit_batch"
                Expression("ENTIRE_WORKTOP")
            ;
            """
        manifest: TransactionManifest = TransactionManifest(
            Instructions.from_string(manifest_string, NETWORK_ID),
            []
        )
        manifest.statically_validate()

        current_epoch: int = GatewayApiClient.current_epoch()
        transaction: NotarizedTransaction = (
            TransactionBuilder()
            .header(
                TransactionHeader(
                    NETWORK_ID,
                    current_epoch,
                    current_epoch + 10,
                    random_nonce(),
                    public_key,
                    True,
                    0,
                )
            )
            .manifest(manifest)
            .message(Message.NONE())
            .notarize_with_private_key(private_key)
        )

        transaction_id: TransactionHash = transaction.intent_hash()

        response = GatewayApiClient.submit_transaction(transaction)

        print("sleepytime")
        time.sleep(8)
        do_markings(account_address, private_key, public_key)

        return {
            "Transaction ID": transaction_id.as_str(),
            "Response": response
        }

def do_liquidations(account_address, private_key, public_key):
    print("startliqs")
    result = GatewayApiClient.preview_liquidation()

    if result['receipt']['status'] == "Succeeded":
        stab_for_one_liq, xrd_rewarded = extract_resource_amounts(result)
        stab_to_use = stab_for_one_liq * fraction_to_liquidate + 0.001

        manifest_string: str = f"""
            CALL_METHOD
                Address("{account_address.as_str()}")
                "lock_fee"
                Decimal("10")
            ;
            CALL_METHOD
                Address("{PROXY_ADDRESS}")
                "flash_borrow"
                Decimal("{stab_to_use}");

            TAKE_ALL_FROM_WORKTOP
                Address("{STAB_ADDRESS}")
                Bucket("stab");

            CALL_METHOD
                Address("{PROXY_ADDRESS}")
                "liquidate_position_without_marker"
                Bucket("stab")
                true
                0i64
                NonFungibleLocalId("#0#");

            TAKE_ALL_FROM_WORKTOP
                Address("{XRD_ADDRESS}")
                Bucket("xrd");

            CALL_METHOD
                Address("{SWAP_COMPONENT}")
                "swap"
                Bucket("xrd");

            TAKE_ALL_FROM_WORKTOP
                Address("{STAB_ADDRESS}")
                Bucket("stab_bucket");

            TAKE_ALL_FROM_WORKTOP
                Address("{LOAN_RECEIPT_ADDRESS}")
                Bucket("receipt_bucket");

            CALL_METHOD
                Address("{PROXY_ADDRESS}")
                "flash_pay_back"
                Bucket("receipt_bucket")
                Bucket("stab_bucket");

            CALL_METHOD
                Address("{REWARD_ACCOUNT_ADDRESS}")
                "try_deposit_batch_or_abort"
                Expression("ENTIRE_WORKTOP")
                Enum<1u8>(
                    Enum<0u8>(
                        NonFungibleGlobalId("resource_rdx1nfxxxxxxxxxxsecpsgxxxxxxxxx004638826440xxxxxxxxxsecpsg:[2c4f19a2711fa4a8d242a99ff8474d10b572c277a05aed392e69a882cf]")
                    )
                )
            ;
            """
        manifest: TransactionManifest = TransactionManifest(
            Instructions.from_string(manifest_string, NETWORK_ID),
            []
        )
        manifest.statically_validate()

        current_epoch: int = GatewayApiClient.current_epoch()
        transaction: NotarizedTransaction = (
            TransactionBuilder()
            .header(
                TransactionHeader(
                    NETWORK_ID,
                    current_epoch,
                    current_epoch + 10,
                    random_nonce(),
                    public_key,
                    True,
                    0,
                )
            )
            .manifest(manifest)
            .message(Message.NONE())
            .notarize_with_private_key(private_key)
        )

        transaction_id: TransactionHash = transaction.intent_hash()

        response = GatewayApiClient.submit_transaction(transaction)

        time.sleep(8)
        do_liquidations(account_address, private_key, public_key)

        return {
            "Transaction ID": transaction_id.as_str(),
            "Response": response
        }


def lambda_handler(event, context):
    try:
        private_key_hex = 'fb1f9b0610351cd240a9cf8f6f52373949840e516100512cba27b6bb4c7c9e07'
        existing_private_key_bytes = bytes.fromhex(private_key_hex)
        (private_key, public_key, account_address) = account_from_keys(NETWORK_ID)

        print(f"Private key is associated with the account: {account_address.as_str()}")

        price_data, signature, xrd_price = get_xrd_price()

        manifest_string: str = f"""
            CALL_METHOD
            Address("{account_address.as_str()}")
            "lock_fee"
            Decimal("10")
            ;
            CALL_METHOD
            Address("{ORACLE_ADDRESS}")
            "set_price"
            "{price_data}"
            "{signature}"
            ;
            CALL_METHOD
            Address("{PROXY_ADDRESS}")
            "update"
            ;
            CALL_METHOD
            Address("{DAO_ADDRESS}")
            "rewarded_update"
            ;
            CALL_METHOD
                Address("{REWARD_ACCOUNT_ADDRESS}")
                "try_deposit_batch_or_abort"
                Expression("ENTIRE_WORKTOP")
                Enum<1u8>(
                    Enum<0u8>(
                        NonFungibleGlobalId("resource_rdx1nfxxxxxxxxxxsecpsgxxxxxxxxx004638826440xxxxxxxxxsecpsg:[2c4f19a2711fa4a8d242a99ff8474d10b572c277a05aed392e69a882cf]")
                    )
                )
            ;
        """
        manifest: TransactionManifest = TransactionManifest(
            Instructions.from_string(manifest_string, NETWORK_ID),
            []
        )
        manifest.statically_validate()

        current_epoch: int = GatewayApiClient.current_epoch()
        transaction: NotarizedTransaction = (
            TransactionBuilder()
            .header(
                TransactionHeader(
                    NETWORK_ID,
                    current_epoch,
                    current_epoch + 10,
                    random_nonce(),
                    public_key,
                    True,
                    0,
                )
            )
            .manifest(manifest)
            .message(Message.NONE())
            .notarize_with_private_key(private_key)
        )

        transaction_id: TransactionHash = transaction.intent_hash()

        response = GatewayApiClient.submit_transaction(transaction)

        arbitrage(xrd_price, account_address, private_key, public_key)
        do_markings(account_address, private_key, public_key)
        do_liquidations(account_address, private_key, public_key)

        return {
            "Transaction ID": transaction_id.as_str(),
            "Response": response
        }

    except Exception as e:
        print(f"An error occurred: {e}")
        raise

lambda_handler(None, None)




