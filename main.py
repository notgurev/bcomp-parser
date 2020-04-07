import sys
import time
import csv

def hex_to_binary(s):
    hex_list = list(s)
    for i in range(0, len(hex_list)):
        temp = bin(int(hex_list[i], 16)).split('b')[1]
        while len(temp) < 4:
            temp = '0' + temp
        hex_list[i] = temp
    binary = ''.join(hex_list)
    return binary


def binary_to_signed_16(x):
    if x[0] == '0':
        return hex(int(x, 2)).lstrip('0x')
    else:
        x = list(x)
        for i in range(0, len(x)):
            if x[i] == '1':
                x[i] = '0'
            else:
                x[i] = '1'
        x = ''.join(x)
        x = hex(int(x, 2)+1).lstrip('0x')
        return '-'+x.upper()


def adr_com(x):
    a_kop = {
        '2': ('AND %s', 'Логическое умножение'),
        '3': ('OR %s', 'Логическое или'),
        '4': ('ADD %s', 'Сложение'),
        '5': ('ADC %s', 'Сложение с переносом'),
        '6': ('SUB %s', 'Вычитание'),
        '7': ('CMP %s', 'Сравнение'),
        '8': ('LOOP %s', 'Декремент и пропуск'),
        '9': ('', 'Резерв'),
        'A': ('LD %s', 'Загрузка'),
        'B': ('SWAM %s', 'Обмен'),
        'C': ('JUMP %s', 'Переход'),
        'D': ('CALL %s', 'Вызов подпрограммы'),
        'E': ('ST %s', 'Сохранение'),
    }
    x_bin = hex_to_binary(x)
    # Анализ адресации
    if x_bin[4] == '0':
        info = '(Прямая абсолютная адресация)'
        # В мнемонику записываем адрес
        m = '0x' + x[1:4].lstrip('0')
    elif x_bin[4] == '1':
        if x[1] == 'F':
            info = '(Прямая загрузка операнда)'
            # В мнемонику записываем операнд
            m = '#0x' + x[2:4]
        else:
            mode = x_bin[5:8]
            offset = binary_to_signed_16(x_bin[8:16]).upper()
            if offset[0] != '-':
                offset = '+' + offset
            formats = {
                '110': ('IP%s', '(Прямая относительная адресация)'),
                '000': ('(IP%s)', '(Косвенная относительная адресация)'),
                '010': ('(IP%s)+', '(Косвенная относительная автоинкрементная адресация)'),
                '011': ('-(IP%s)', '(Косвенная относительная автодекрементная адресация)'),
                '100': ('(SP%s)', '(Косвенная относительная со смещением)')
            }
            m = formats.get(mode)[0] % offset
            info = formats.get(mode)[1]

    temp = a_kop.get(x[0])
    return temp[0] % m, (temp[1] + ' ' + info)


def bez_adr_com(x):
    b = {
        '0000': ('NOP', 'Нет операции'),
        '0100': ('HLT', 'Остановка'),
        '0200': ('CLA', 'Очистка аккумулятора'),
        '0280': ('NOT', 'Инверсия аккумулятора'),
        '0300': ('CLC', 'Очистка рег. переноса'),
        '0380': ('CMC', 'Инверсия рег. переноса'),
        '0400': ('ROL', 'Циклический сдвиг влево'),
        '0480': ('ROR', 'Циклический сдвиг вправо'),
        '0500': ('ASL', 'Арифметический сдвиг влево'),
        '0580': ('ASR', 'Арифметический сдвиг вправо'),
        '0600': ('SXTB', 'Расширение знака байта'),
        '0680': ('SWAB', 'Обмен ст. и мл. байтов'),
        '0700': ('INC', 'Инкремент'),
        '0740': ('DEC', 'Декремент'),
        '0780': ('NEG', 'Изменение знака'),
        '0800': ('POP', 'Чтение из стэка'),
        '0900': ('POPF', 'Чтение флагов из стэка'),
        '0A00': ('RET', 'Возврат из подпрограммы'),
        '0B00': ('IRET', 'Возврат из прерывания'),
        '0C00': ('PUSH', 'Запись в стэк'),
        '0D00': ('PUSHF', 'Запись флагов в стэк'),
        '0E00': ('SWAP', 'Обмен вершины стэка и аккумулятора')
    }
    return b.get(x)


def vet_com(x):
    v = {
        'F0': ('BEQ %s', 'Переход, если равенство'),
        'F1': ('BNE %s', 'Переход, если неравенство'),
        'F2': ('BMI %s', 'Переход, если минус'),
        'F3': ('BPL %s', 'Переход, если плюс'),
        'F4': ('BLO/BCS %s', 'Переход, если ниже/перенос'),
        'F5': ('BHIS/BCC %s', 'Переход, если выше/нет переноса'),
        'F6': ('BVS %s', 'Переход, если переполнение'),
        'F7': ('BVC %s', 'Переход, если нет переполнения'),
        'F8': ('BLT %s', 'Переход, если меньше'),
        'F9': ('BGE %s', 'Переход, если больше или равно'),
        'CE': ('BR %s', 'Безусловный переход (эквивалент JUMP c прямой относительной адресацией)'),
    }
    x_bin = hex_to_binary(x)
    offset = binary_to_signed_16(x_bin[8:16]).upper()
    if offset[0] != '-':
        offset = '+' + offset
    m = 'IP%s' % offset
    temp = v.get(x[0:2]) 
    return temp[0] % m, temp[1]


def parse_code_to_line(code):
    template = "{0[0]:<15} | {0[1]}"
    try:
        if code[0] == "0":  # безадресная
            return template.format(bez_adr_com(code))
        elif code[0] == "F" or code[0:2] == "CE":  # ветвление
            return template.format(vet_com(code))
        elif code[0] == "1":  # ввода-вывода
            return "Команды ввода-вывода не поддерживаются!"
        elif ("2" <= code[0] <= "9") or ("A" <= code[0] <= "E"):  # адресная
            return template.format(adr_com(code))
        else:
            return "Переменная/ошибка"
    except:
        return "Константа/ошибка"


# Аргументы
show_disclaimer = True
export_to_csv = False

for arg in sys.argv:
    if arg == '-nodisc': show_disclaimer = False
    if arg == '-csv': export_to_csv = True

if show_disclaimer:
    print("""
Будьте внимательны: парсер обрабатывает ВСЕ коды как команды, 
кроме тех, что он не может расшифровать (тогда он пишет, что это переменная или константа).
Однако некоторые коды на самом деле являются константами. Их нужно определять вручную.
(или пофиксить это и кинуть pull request на github.com/notgurev/bcomp-parser)

Напоминаю: парсер сделан только для ПРОВЕРКИ вашего решения. Не стоит на него полагаться.
    """)
    time.sleep(3)


with open('input.txt', 'r', encoding='utf-8') as lines:
    data = []
    for c in lines:
        c = c.replace('\n', '').replace('+', '').strip()
        if len(c) != 4:  # не обрабатываем строки с длиной != 4
            print(c)
            continue
        if export_to_csv:
            data.append(c + ' | ' + parse_code_to_line(c))
        print(c + ' | ' + parse_code_to_line(c))
    if export_to_csv:
        print('\nЭкспортировано в result.csv')


if export_to_csv:
    with open('result.csv', mode='w', newline='', encoding='utf-8') as csv_file:
        fieldnames = ['Код команды', 'Мнемоника', 'Информация']
        csv_writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        csv_writer.writeheader()
        for row in data:
            splitted = [x.strip() for x in row.split('|')]
            if len(splitted) == 2 and 'ошибка' in splitted[1]:  # костыль
                splitted.append(splitted[1])
                splitted[1] = ""
            csv_writer.writerow({'Код команды': splitted[0], 'Мнемоника': splitted[1], 'Информация': splitted[2]})