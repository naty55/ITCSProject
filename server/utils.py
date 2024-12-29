valid_phone_numbers = {str(i) * 9 for i in range(10)} # phone number is of pattern "ddddddddd" e.g. "111111111"

def validate_phone_number(phone_number):
    return phone_number in valid_phone_numbers