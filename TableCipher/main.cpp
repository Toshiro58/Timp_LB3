#include "modTableCipher.h"
#include <UnitTest++/UnitTest++.h>
#include <iostream>
#include <limits>
#include <locale>
#include <string>
#include <codecvt>


using namespace std;
wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> codec;
SUITE(KeyTest)
{
    TEST(ValidKey) {
        CHECK_EQUAL("ШКОААВБМО", codec.to_bytes((TableCipher(L"3").encrypt(L"БАШМАКОВО"))));
    }
    TEST(NegativeKey) {
        CHECK_THROW(TableCipher cp(L"-5"),cipher_error);
    }
    TEST(WhitespaceInKey) {
        CHECK_THROW(TableCipher cp(L"52 5"),cipher_error);
    }
    TEST(EmptyKey) {
        CHECK_THROW(TableCipher cp(L""),cipher_error);
    }
    TEST(NotNumbers) {
        CHECK_THROW(TableCipher cp(L"Хай,"),cipher_error);
    }
	TEST(TheKeyExceedsHalfTheText) {
	    TableCipher cp(L"8");
        CHECK_THROW(cp.encrypt(L"БАШМАЧКОВО"),cipher_error);
    }
}

struct KeyB_fixture {
    TableCipher * p;
    KeyB_fixture()
    {
        p = new TableCipher(L"3");
    }
    ~KeyB_fixture()
    {
        delete p;
    }
};

SUITE(EncryptTest)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        CHECK_EQUAL("ШКОААВБМО",
                    codec.to_bytes(p->encrypt(L"БАШМАКОВО")));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        CHECK_EQUAL("ШКОААВБМО",
                    codec.to_bytes(p->encrypt(L"башмаково")));
    }
    TEST_FIXTURE(KeyB_fixture, StringWithNumbers) {
        CHECK_EQUAL("ШКОААВБМО", codec.to_bytes(p->encrypt(L"БАШМАКОВО1232323")));
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(p->encrypt(L""),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, NoAlphaString) {
        CHECK_THROW(p->encrypt(L"1676765545454"),cipher_error);
    }
}

SUITE(DecryptText)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        CHECK_EQUAL("БАШМАКОВО",
                    codec.to_bytes(p->decrypt(L"ШКОААВБМО")));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        CHECK_THROW(p->decrypt(L"ШКоААВбмО"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, WhitespaceString) {
        CHECK_THROW(p->decrypt(L"Ш КО АА ВБ МО"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, DigitsString) {
        CHECK_THROW(p->decrypt(L"ШКОААВ52БМО"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, PunctString) {
        CHECK_THROW(p->decrypt(L"ШКОАА,,,,,ВБМО"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(p->decrypt(L""),cipher_error);
    }
}


int main(int argc, char **argv)
{
    locale loc("ru_RU.UTF-8");
    locale::global(loc);
    return UnitTest::RunAllTests();
}
