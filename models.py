from typing import List, Dict


class Result:
    def __init__(self, status_code: int, message: str = '', data: List[Dict] = None):
        """
        A generic wrapper for the response of an HTTP request.
        :param status_code: The response status code.
        :param message: The response message.
        :param data: The response data as a list of dictionaries.
        """
        self.def_err_msg = None
        self.status_code = int(status_code)
        self.message = str(message)
        self.data = data if data else []
        # Use is format ready for the Log/Func location, the message and data length returned

    def add_error_message(self, log_loc: str):
        self.def_err_msg = "{} Result not ok. Message: {} Data Len: {}"
        return self.def_err_msg.format(log_loc, self.message, len(self.data))

    def print(self):
        print(f"Status code: {self.status_code}", end=", ")
        print(f"Message: {self.message}", end=", ")
        print(f"Data: {self.data}")

    def is_ok(self):
        # Todo: does this need a flag? An optional "if no data then there is error?" -- It's ok to return an empty list
        # if not self.data:
        #     return False
        if self.message != "OK":
            return False
        return True

    def data_len(self):
        return 0 if not self.data else len(self.data)
