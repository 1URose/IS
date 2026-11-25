# Лабораторные работы по информационной безопасности

Независимая учебная реализация четырёх криптографических лабораторных работ
на Python 3.9+. Алгоритмы реализованы в `security_labs/core` без готовых
криптографических библиотек; используются только стандартная библиотека и
`secrets` для криптографически стойкой случайности.

## Состав и план реализации

| Лаба | Модуль | Результат |
| --- | --- | --- |
| 1 | RSA-32768 | ключи, PKCS#1 v1.5, шифрование текста и файлов |
| 2 | Кузнечик | ГОСТ Р 34.12-2015, CTR, пароль и проверка целостности |
| 3 | Стрибог | ГОСТ Р 34.11-2012, 256/512, HMAC, PBKDF2 и пароли |
| 4 | ЭЦП | ГОСТ Р 34.10-2012, ключи, подпись файлов и PDF |

Общая последовательность: математическое ядро и RSA; затем Стрибог как
общая хеш-функция; Кузнечик с контейнером файла; затем ЭЦП, использующая
Стрибог. Каждый этап покрыт контрольными векторами стандарта.

## Запуск

Команды выполняются из корня проекта:

```powershell
python -m unittest discover -v
python -m security_labs.lab1_rsa demo
python -m security_labs.lab1_rsa keygen --bits 2048 --out results/keys/demo
python -m security_labs.lab1_rsa encrypt --key results/keys/demo.public.json --text "Привет" --out results/lab1/message.rsa
python -m security_labs.lab1_rsa decrypt --key results/keys/demo.private.json --in results/lab1/message.rsa
python -m security_labs.lab2_kuznyechik demo
python -m security_labs.lab2_kuznyechik encrypt --password demo --text "Секрет" --out results/lab2/message.kzc
python -m security_labs.lab3_streebog demo
python -m security_labs.lab3_streebog hash --bits 512 --text "Сообщение"
python -m security_labs.lab4_signature demo
python -m security_labs.lab4_signature keygen --out results/keys/alice
python -m security_labs.lab4_signature sign --key results/keys/alice.private.json --file document.txt --sig results/lab4/document.sig
python -m security_labs.lab4_signature verify --key results/keys/alice.public.json --file document.txt --sig results/lab4/document.sig
```

### Лабораторная 1 — RSA-32768

```powershell
# Быстрая защита: учебный пример + RSA-512, чтобы не ждать генерацию.
python -m security_labs.lab1_rsa demo

# Обязательный полный вариант. Генерация может занимать десятки минут.
python -m security_labs.lab1_rsa keygen --bits 32768 --out results/keys/rsa32768
python -m security_labs.lab1_rsa encrypt --key results/keys/rsa32768.public.json --in input.bin --out results/lab1/input.rsa
python -m security_labs.lab1_rsa decrypt --key results/keys/rsa32768.private.json --in results/lab1/input.rsa --out results/lab1/input.restored.bin

# Интеграционная проверка сохранённого ключа RSA-32768. Если ключ отсутствует,
# тест будет явно отмечен как пропущенный, а не станет генерировать ключ заново.
python -m unittest tests.test_rsa32768_integration -v
```

### Лабораторная 2 — Кузнечик

```powershell
python -m security_labs.lab2_kuznyechik demo
python -m security_labs.lab2_kuznyechik encrypt --password 'Пароль-2026!' --in input.bin --out results/lab2/input.kzc
python -m security_labs.lab2_kuznyechik decrypt --password 'Пароль-2026!' --in results/lab2/input.kzc --out results/lab2/input.restored.bin
# Неверный пароль или изменённый контейнер будет отклонён до расшифрования.
```

### Лабораторная 3 — Стрибог

```powershell
python -m security_labs.lab3_streebog demo
python -m security_labs.lab3_streebog hash --bits 512 --file input.bin
python -m security_labs.lab3_streebog hash --bits 256 --text 'Сообщение'
python -m security_labs.lab3_streebog password
# Скопируйте выданную строку pbkdf2-streebog512$... в --stored.
python -m security_labs.lab3_streebog check --stored 'pbkdf2-streebog512$200$...$...'
```

### Лабораторная 4 — ЭЦП ГОСТ

```powershell
python -m security_labs.lab4_signature demo
python -m security_labs.lab4_signature keygen --out results/keys/alice
python -m security_labs.lab4_signature sign --key results/keys/alice.private.json --file input.bin --sig results/lab4/input.sig
python -m security_labs.lab4_signature verify --key results/keys/alice.public.json --file input.bin --sig results/lab4/input.sig
python -m security_labs.lab4_signature sign-pdf --key results/keys/alice.private.json --file document.pdf --out results/lab4/document.signed.pdf
python -m security_labs.lab4_signature verify-pdf --key results/keys/alice.public.json --file results/lab4/document.signed.pdf
```

Для требуемого ключа используйте `keygen --bits 32768`. Это намеренно долгий
процесс: два простых числа по 16 384 бита генерируются и проверяются
самостоятельно. Результаты команд сохраняются в `results/`.

Команда `sign-pdf` сохраняет учебную встроенную подпись в комментарии после
конца PDF: подписываются исходные байты PDF, а в записи присутствуют подпись,
параметры кривой и открытый ключ. Это сохраняет отображение документа обычным
PDF-просмотрщиком; проверка выполняется командой `verify-pdf` с отдельным
доверенным открытым ключом, а не средствами Adobe/PAdES.
Полные ограничения и граница с PAdES описаны в [docs/pdf_signature.md](docs/pdf_signature.md).

## Соответствие ТЗ

- RSA использует два простых по 16 384 бита в режиме `--bits 32768`, `e=65537`,
  Миллера-Рабина, расширенный Евклид, собственное возведение в степень, CRT и
  случайное PKCS#1 v1.5 дополнение.
- «Кузнечик» реализован как ГОСТ Р 34.12-2015, а режим CTR использует новый
  64-битный IV при каждом шифровании; контейнер защищён HMAC-Стрибогом.
- Стрибог реализует 256 и 512 бит; для паролей используются случайная соль и
  PBKDF2-HMAC-Стрибог.
- ЭЦП реализует ГОСТ Р 34.10-2012 с самописными операциями эллиптической
  кривой и внутренним Стрибогом. PDF-подпись является учебной, не PAdES.

## Структура

```
security_labs/
  core/       # криптография и кодеки ключей
  lab1_rsa.py # самостоятельные консольные точки входа
  lab2_kuznyechik.py
  lab3_streebog.py
  lab4_signature.py
tests/        # автоматические и контрольные тесты
results/      # создаётся командами, не хранит исходный код
```

Учебный проект: реализации предназначены для демонстрации алгоритмов, а не
для защиты реальных секретных данных.
