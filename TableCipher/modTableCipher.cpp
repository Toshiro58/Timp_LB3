#include "modTableCipher.h"

#include <algorithm>
#include <iostream>
#include <locale>
#include <string>

using namespace std;

TableCipher::TableCipher(const std::wstring &key_str)
    : key(getValidKey(key_str)) {}
std::wstring TableCipher::encrypt(const std::wstring &text) {
 
  wstring tmp = getValidOpenText(text);
  if (key > static_cast<int>(text.length()) / 2) {
    throw cipher_error("Длина ключа не должна превышать половину длины текста");
  }
  int rows =
      static_cast<int>((tmp.length() + key - 1) / key); 
  wchar_t table[rows][key];

  
  int index = 0; 
  for (int i = 0; i < rows; i++) { 
    for (int j = 0; j < key; j++) { 
      if (index < static_cast<int>(tmp.length())) {
        table[i][j] = tmp[index];
        index++;
      } else {
        table[i][j] = L' ';
      }
    }
  }

  std::wstring encrypted_text; 

  
  for (int i = key - 1; i >= 0; i--) {
    for (int j = 0; j < rows; j++) {
      if (table[j][i] == L' ') {
        encrypted_text +=
            L'*'; 
      } else {
        encrypted_text += table[j][i];
      }
    }
  }

  return encrypted_text;
}

std::wstring TableCipher::decrypt(const std::wstring &encrypted_text) {
  wstring tmp = getValidCipherText(encrypted_text);
  int rows = static_cast<int>((tmp.length() + key - 1) / key);
  wchar_t table[rows][key];

  int index = 0;
  for (int i = key - 1; i >= 0; i--) {
    for (int j = 0; j < rows; ++j) {
      if (index < static_cast<int>(tmp.length())) {
        table[j][i] = tmp[index];
        index++;
      } else {
        table[j][i] = L' ';
      }
    }
  }

  std::wstring decrypted_text;
  index = 0;
  for (int i = 0; i < rows; i++) {
    for (int j = 0; j < key; j++) {
      if (table[i][j] == L'*') {
        decrypted_text += L' '; 
      } else {
        decrypted_text += table[i][j];
      }
    }
  }
  decrypted_text.erase(
      std::remove(decrypted_text.begin(), decrypted_text.end(), ' '),
      decrypted_text.end());
  return decrypted_text;
}

inline std::wstring TableCipher::getValidOpenText(const std::wstring &s) {
  std::wstring tmp;
  for (auto c : s) {
    if (iswalpha(c)) {
      if (iswlower(c))
        tmp.push_back(towupper(c));
      else
        tmp.push_back(c);
    } else if (iswspace(c)) {
      tmp.push_back(c);
    }
  }
  if (tmp.empty())
    throw cipher_error("Пустой открытый текст");
  return tmp;
}

inline std::wstring TableCipher::getValidCipherText(const std::wstring &s) {
  if (s.empty())
    throw cipher_error("Пустой зашифрованный текст");

  std::wstring tmp(s);
  std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;
  std::string m = converter.to_bytes(tmp);

  for (auto c : s) {
    if (c == L'*') {
      continue;
    }
    if (!iswupper(c)) {
      throw cipher_error(std::string("Неправильный зашифрованный текст : ") +
                         m);
    }
  }
  return tmp;
}

int TableCipher::getValidKey(const std::wstring &key_str) {
  if (key_str.empty())
    throw cipher_error("Пустой ключ");

  for (auto &c : key_str) {
    if (!iswdigit(c)) {
      throw cipher_error("Некорректный ключ: " +
                         std::string(key_str.begin(), key_str.end()));
    }
  }

  int key = std::stoi(std::string(key_str.begin(), key_str.end()));
  if (key <= 0) {
    throw cipher_error("Ключ не должен быть <= 0");
  }
  return key;
}
