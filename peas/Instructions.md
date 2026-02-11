## Как запускать pEAS, чтобы показать наши доработки

## 1) Доработка поиска по ключевым словам
Здесь надо написать команду запуска с нужными флагами

## 2) Доработка листинга на шарах больше 1000 записей

Cтарая версия (без цикла):
```bash
python2 -m peas -u 'TESTLAB\testuser' -p 'P@ssw0rd' 192.168.56.102 \
  --list-unc '\WIN-25B1LEVJHUO\many' 
  ```
Новая версия с paging

```bash
PYTHONPATH=. python2 -m peas \
  -u 'TESTLAB\testuser' -p 'P@ssw0rd' 192.168.56.102 \
  --list-unc '\WIN-25B1LEVJHUO\many' \
  --unc-page-size 500 --debug-unc -o list.txt
  ```

## 3) Доработка экспорта писем в корректный EML
Из корня проекта (старая версия):

```bash
python2 -m peas -u 'TESTLAB\testuser' -p 'P@ssw0rd' 192.168.56.102 --emails
```
Из корня проекта (новая версия):
```bash
python2 peas/__main__.py -u 'TESTLAB\testuser' -p 'P@ssw0rd' -O out 192.168.56.102 --emails
```

## 4) Доработка фильтрации писем по наличию пользователя в роли отправителя и/или получателя
```bash
python2 -m peas -u 'TESTLAB\testuser' -p 'P@ssw0rd' 192.168.56.102 --emails --person Administrator --direction from
```

## 5) Доработка 5
