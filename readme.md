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

![Test case images](./screenshots/coverage_report_sq3.PNG)

**POST test using insomnia:**<br>
I have no ided how to automatically generate 2 keys that will expired in 1 second and 1 minute so I have created 2 end points to manually generate them <br>
1 second expired <br>
![POST test images 1 second](./screenshots/1_second_expire_key.PNG)
1 minute expired <br>
![POST test images 1 minute](./screenshots/1_minute_expire_key.PNG)
POST test with /auth endpoint <br>
![POST test images sqlite](./screenshots/POST_test_sqlite.PNG)

**GET test using insomnia:**<br>

![GET test images](./screenshots/GET_test_sglite.PNG)

**Blackbox testing:**<br>
For unknown reasons, I am not able to run the executable file that is provided. Everytime I tried to run it, a window flash on my screen for like 1 frame and then dissapear<br>
Due to that reason, I am not able to provide a screenshot for it.<br>
