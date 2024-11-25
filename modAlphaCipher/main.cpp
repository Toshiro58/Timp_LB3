#include "modAlphaCipher.h"

#include <UnitTest++/UnitTest++.h>
#include <codecvt>
#include <locale>
#include <string>
using namespace std;

wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> codec;

// Тестирование ключей
SUITE(KeyTest)
{
    TEST(ValidKey) {
        CHECK_EQUAL("ХЪЛНПЬР", codec.to_bytes(modAlphaCipher(L"КЛЮЧ").encrypt(L"КОНЦЕРТ")));
    }
    TEST(LongKey) {
        CHECK_EQUAL("ЦЪУЫУ", codec.to_bytes(modAlphaCipher(L"ДЛИТЕЛЬНЫЙКЛЮЧ").encrypt(L"ТОКИО")));
    }
    TEST(DigitsInKey) {
        CHECK_THROW(modAlphaCipher cp(L"КЛЮЧ123"), cipher_error);
    }
    TEST(PunctuationInKey) {
        CHECK_THROW(modAlphaCipher cp(L"КЛ,ЮЧ!"), cipher_error);
    }
    TEST(WhitespaceInKey) {
        CHECK_THROW(modAlphaCipher cp(L"К ЛЮ Ч"), cipher_error);
    }
    TEST(EmptyKey) {
        CHECK_THROW(modAlphaCipher cp(L""), cipher_error);
    }
    TEST(WeakKey) {
        CHECK_THROW(modAlphaCipher cp(L"AAA"), cipher_error);
    }
}

// Структура для создания и удаления объекта modAlphaCipher
struct KeyB_fixture {
    modAlphaCipher* p;
    KeyB_fixture() { p = new modAlphaCipher(L"ТЕСТ"); }
    ~KeyB_fixture() { delete p; }
};

// Тесты на шифрование
SUITE(EncryptTest)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        CHECK_EQUAL("УЕЙЯТПАФБХСЬДПАЧЯЙГЕБ", 
                    codec.to_bytes(p->encrypt(L"БАШМАКОВОРАЙСКОЕМЕСТО")));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        CHECK_EQUAL("УЕЙЯТПАФБХСЬДПАЧЯЙГЕБ", 
                    codec.to_bytes(p->encrypt(L"башмаковорайскоеместо")));
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(p->encrypt(L""), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, NoAlphaString) {
        CHECK_THROW(p->encrypt(L"1234+8765=9999"), cipher_error);
    }
    TEST(MaxShiftKey) {
        CHECK_EQUAL("АЯЧЛЯЙНБНПЯИРЙНДЛДРСНЙТГЯФНЦДСРЮБРДВГЯБДПМТСЫРЮ",
                    codec.to_bytes(modAlphaCipher(L"Я").encrypt(L"БАШМАКОВОРАЙСКОЕМЕСТОКУДАХОЧЕТСЯВСЕГДАВЕРНУТЬСЯ")));
    }
    
}

// Тесты на расшифровку
SUITE(DecryptTest)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        CHECK_EQUAL("БАШМАКОВОРАЙСКОЕМЕСТО",
                    codec.to_bytes(p->decrypt(L"УЕЙЯТПАФБХСЬДПАЧЯЙГЕБ")));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        CHECK_THROW(p->decrypt(L"бАшМАКОВОРАЙСКОЕМЕСТО"), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, WhitespaceString) {
        CHECK_THROW(p->decrypt(L"БАШМАКОВО РАЙСКОЕ МЕСТО "), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, DigitsString) {
        CHECK_THROW(p->decrypt(L"БАШМАКОВО52"), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, PunctString) {
        CHECK_THROW(p->decrypt(L"БАШМАКОВО, 52."), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(p->decrypt(L""), cipher_error);
    }
    TEST(MaxShiftKey) {
        CHECK_EQUAL("БАШМАКОВОРАЙСКОЕМЕСТОКУДАХОЧЕТСЯВСЕГДАВЕРНУТЬСЯ",
                    codec.to_bytes(modAlphaCipher(L"Я").decrypt(L"АЯЧЛЯЙНБНПЯИРЙНДЛДРСНЙТГЯФНЦДСРЮБРДВГЯБДПМТСЫРЮ")));
    }
}

int main() {
    locale loc("ru_RU.UTF-8");
    locale::global(loc);
    return UnitTest::RunAllTests();
}
