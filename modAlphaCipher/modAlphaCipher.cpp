#include "modAlphaCipher.h"

#include <codecvt>

modAlphaCipher::modAlphaCipher(const std::wstring& skey)
{
    for(unsigned i = 0; i < numAlpha.size(); i++) {
        alphaNum[numAlpha[i]] = i;
    }
    key = convert(getValidKey(skey));
    size_t n = 0;
    for(auto e : key) {
        if(e == 0)
            n++;
    }
    if(2 * n > key.size())
        throw cipher_error("WeakKey");
}
std::wstring modAlphaCipher::encrypt(const std::wstring& open_text)
{
    std::vector<int> work = convert(getValidOpenText(open_text));
    for(unsigned i = 0; i < work.size(); i++) {
        work[i] = (work[i] + key[i % key.size()]) % alphaNum.size();
    }
    return convert(work);
}
std::wstring modAlphaCipher::decrypt(const std::wstring& cipher_text)
{
    std::vector<int> work = convert(getValidCipherText(cipher_text));
    for(unsigned i = 0; i < work.size(); i++) {
        work[i] = (work[i] + alphaNum.size() - key[i % key.size()]) % alphaNum.size();
    }
    return convert(work);
}
inline std::vector<int> modAlphaCipher::convert(const std::wstring& s)
{
    std::vector<int> result;
    for(auto c : s) {
        result.push_back(alphaNum[c]);
    }
    return result;
}
inline std::wstring modAlphaCipher::convert(const std::vector<int>& v)
{
    std::wstring result;
    for(auto i : v) {
        result.push_back(numAlpha[i]);
    }
    return result;
}

inline std::wstring modAlphaCipher::getValidKey(const std::wstring& s)
{
    if(s.empty())
        throw cipher_error("Пустой ключ");

    std::wstring tmp(s);
    std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;
    std::string m = converter.to_bytes(tmp);
    for(auto& c : tmp) {
        if(!iswalpha(c)) {
            throw cipher_error(std::string("Неправильный ключ: ") + m);
        }
        if(iswlower(c)) {
            c = towupper(c);
        }
    }
    return tmp;
}

inline std::wstring modAlphaCipher::getValidOpenText(const std::wstring& s)
{
    std::wstring tmp;
    for(auto c : s) {
        if(iswalpha(c)) {
            if(iswlower(c))
                tmp.push_back(towupper(c));
            else
                tmp.push_back(c);
        }
    }
    if(tmp.empty())
        throw cipher_error("Пустой открытый текст");
    return tmp;
}

inline std::wstring modAlphaCipher::getValidCipherText(const std::wstring& s)
{
    if(s.empty())
        throw cipher_error("Empty cipher text");

    std::wstring tmp(s);
    std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;
    std::string m = converter.to_bytes(tmp);

    for(auto c : s) {
        if(!iswupper(c))
            throw cipher_error(std::string("Неправильный зашифрованный текст : ") + m);
    }

    return tmp;
}
