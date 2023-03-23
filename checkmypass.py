import requests
import hashlib
import sys


def request_api_data(query_char):
    url = "https://api.pwnedpasswords.com/range/" + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again')
    return res


def get_password_leaks_count(hashes, hash_to_check):
    """hashes.text will contain all the SHA1 responses (tail - leaving the first five char)
    received from URL. The statement [hashes.text.splitlines()] will convert this into a list.
    The following statement is converting the list into a tuple generator object with
    tuple comprehension """
    hashes = (line.split(':') for line in hashes.text.splitlines())
    # Loop through the tuple to get the hash value and the count of passwords already leaked.
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


# check password if it exists in API response
def pwned_api_check(password):
    # converting the password to SHA1
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    # Only first 5 char is sent to request_api_data function. Below code to split the sha1password
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)

    # print(first5_char, tail, response)
    return get_password_leaks_count(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times...you should probably change your password!')
        else:
            print(f'{password} was not found. Carry On')
    return 'Done!'


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
