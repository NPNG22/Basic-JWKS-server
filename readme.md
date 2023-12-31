# Basic JWKS server implementation

This is a basic implementation of a JWKS server using Python with Flask and Cryptography, now with added Sqlite3 database

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Test](#test)
- [Result](#result)

## Installation

This project use Python 3.11.5
To run the server, make sure you have Flask and Cryptography installed on your machine

To install Flask:<br>
**pip install Flask**

To install Cryptography:<br>
**pip install cryptography**

To conduct tests using the provided test file, you need to have Coverage:<br>
**pip install coverage**

## Usage

To run the server simply do:<br>
**python -m server**

## Test

I have written in total 7 test cases for the server. You can see them in test.py
I am using Unittest for testing and Coverage for the report

Running coverage with it not in $PATH:<br>
**python -m coverage run test**<br>
**python -m coverage report** (to see the report)<br>

Running with coverage in $PATH:<br>
**coverage run test**<br>
**coverage report** (to see the report)<br>

## Result

Here you can see screenshots of my tests with my own tests, POST and GET tests using Insomnia, and a blackbox test that you can access<br>
Here: https://github.com/jh125486/CSCE3550/releases

**My own test file:**<br>

![Test case images](./screenshots/project3_coverage_report.PNG.PNG)

**Register test using insomnia:**<br>
![Register test images ](./screenshots/Register_test.PNG)

**Auth test using insomnia:**<br>

![Auth test images](./screenshots/Authenticate_with_new_register_test.PNG)

**Blackbox testing:**<br>

![Gradebot test images](./screenshots/project3_gradebot_test.PNG)
