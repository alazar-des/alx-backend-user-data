#!/usr/bin/env python3
"""obfuscate fields with given string."""

import re
from typing import List
import logging
import os
import mysql.connector


PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def filter_datum(fields: List[str], redaction: str, message: str,
                 separator: str) -> str:
    """Replace string with in message with redaction"""
    for fld in fields:
        message = re.sub(r"{}=.+?{}".format(fld, separator),
                         r" {}={}{}".format(fld, redaction, separator), message)
    return message


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields=None):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """filter LogRecord with filter_datum"""
        orignal = logging.Formatter.format(self, record)
        return filter_datum(self.fields, self.REDACTION,
                            orignal, self.SEPARATOR)


def get_logger() -> logging.Logger:
    """ return logger object"""
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    formatter = logging.Formatter(RedactingFormatter(PII_FIELDS))

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.INFO)
    stream_handler.setFormatter(formatter)

    logger.addHandler(stream_handler)

    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """connect to secure database."""
    return mysql.connector.connect(host=os.environ["PERSONAL_DATA_DB_HOST"],
                                   database=os.environ[
                                       "PERSONAL_DATA_DB_NAME"],
                                   user=os.environ[
                                       "PERSONAL_DATA_DB_USERNAME"],
                                   password=os.environ[
                                       "PERSONAL_DATA_DB_PASSWORD"])


if __name__ == "__main__":
    """ read all from table and  obfuscated
    """
    db_connection = get_db()
    cursor = db_connection.cursor()

    query = """SELECT * FROM users;"""

    cursor.execute(query)
    records = cursor.fetchall()

    formatter = RedactingFormatter(PII_FIELDS)
    cols_name = ("name", "email", "phone", "ssn", "password", "ip",
                 "last_login", "user_agent")
    for record in records:
        message = ""
        for (col_name, col_rec) in zip(cols_name, record):
            message += col_name + "=" + str(col_rec) + ";"

        log_record = logging.LogRecord(
            "user_data", logging.INFO, None, None, message, None, None)
        print(formatter.format(log_record))

    cursor.close()
    db_connection.close()
