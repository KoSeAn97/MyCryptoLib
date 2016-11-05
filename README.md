# Encryptor With Kuznyechik
Реализованы:
* Алгоритм блочного шифрования Kuznyechik с длиной блока 128 бит и длиной ключа 256 бит
* Режим шифрования Cipher Feedback и Output Feedback

Планируется реализовать
* Алгоритм блочного шифрования AES-256

## Пример запуска тестовой программы
    make all
    ./program -P path-to-src.txt -D path-to-dst.txt -e
## Вызов справки
    ./program --help
