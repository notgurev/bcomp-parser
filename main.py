# готово к 3 лабе по ОПД
import time

def hex_to_binary(s):
    hex_list = list(s)
    for i in range(0, len(hex_list)):
        # hex_list[i] = d.get(hex_list[i])
        temp = bin(int(hex_list[i], 16)).split('b')[1]
        while (len(temp) < 4):
            temp = '0' + temp
        hex_list[i] = temp
    binary = ''.join(hex_list)
    return binary


def binary_to_signed_16(x):
    # говнокод
    if x[0] == '0':
        return hex(int(x, 2)).lstrip('0x').capitalize()
    else:
        x = list(x)
        for i in range(0, len(x)):
            if x[i] == '1':
                x[i] = '0'
            else:
                x[i] = '1'
        x = ''.join(x)
        x = hex(int(x, 2)+1).lstrip('0x').capitalize()
        return '-'+x.capitalize()


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
    m = 'error'
    info = ''
    if x_bin[4] == '0':
        # Прямая абсолютная адресация
        # В мнемонику записываем адрес
        info = '(Прямая абсолютная адресация)'
        m = '0x' + x[1:4].lstrip('0')
    if x_bin[4] == '1':
        if x[1] == 'F':
            # Прямая загрузка операнда (записываем в info)
            info = '(Прямая загрузка операнда)'
            # В мнемонику записываем операнд
            m = '#0x' + x[2:4]
        else:
            mode = x_bin[5:8]
            offset = binary_to_signed_16(x_bin[8:16])
            if mode == '110':
                # Прямая относительная адресация (записываем в info)
                info = '(Прямая относительная адресация)'
                # В мнемонику записываем смещение
                if offset[0] != '-': #этот ужас надо как-то убрать
                    m = 'IP+%s' % offset
                else:
                    m = 'IP%s' % offset
            elif mode == '000':
                # Косвенная относительная адресация (записываем в info)
                info = '(Косвенная относительная адресация)'
                if offset[0] != '-':
                    m = '(IP+%s)' % offset
                else:
                    m = '(IP%s)' % offset
            elif mode == '010':
                # Косвенная относительная автоинкрементная адресация (записываем в info)
                info = '(Косвенная относительная автоинкрементная адресация)'
                if offset[0] != '-':
                    m = '(IP+%s)+' % offset
                else:
                    m = '(IP%s)+' % offset
            elif mode == '011':
                # Косвенная относительная автодекрементная адресация (записываем в info)
                info = '(Косвенная относительная автодекрементная адресация)'
                if offset[0] != '-':
                    m = '(IP+%s)-' % offset
                else:
                    m = '(IP%s)-' % offset
            elif mode == '100':
                # Косвенная относительная со смещением (SP)
                info = '(Косвенная относительная со смещением)'
                if offset[0] != '-':
                    m = '(SP+%s)' % offset
                else:
                    m = '(SP%s)' % offset

    temp = a_kop.get(x[0])
    return temp[0] % m, temp[1], info


def bez_adr_com(x):
    b = {
        '0000': ('NOP ', 'Нет операции'),
        '0100': ('HLT ', 'Остановка'),
        '0200': ('CLA ', 'Очистка аккумулятора'),
        '0280': ('NOT ', 'Инверсия аккумулятора'),
        '0300': ('CLC ', 'Очистка рег. переноса'),
        '0380': ('CMC ', 'Инверсия рег. переноса'),
        '0400': ('ROL ', 'Циклический сдвиг влево'),
        '0480': ('ROR ', 'Циклический сдвиг вправо'),
        '0500': ('ASL ', 'Арифметический сдвиг влево'),
        '0580': ('ASR ', 'Арифметический сдвиг вправо'),
        '0600': ('SXTB ', 'Расширение знака байта'),
        '0680': ('SWAB ', 'Обмен ст. и мл. байтов'),
        '0700': ('INC ', 'Инкремент'),
        '0740': ('DEC ', 'Декремент'),
        '0780': ('NEG ', 'Изменение знака'),
        '0800': ('POP ', 'Чтение из стэка'),
        '0900': ('POPF ', 'Чтение флагов из стэка'),
        '0A00': ('RET ', 'Возврат из подпрограммы'),
        '0B00': ('IRET ', 'Возврат из прерывания'),
        '0C00': ('PUSH ', 'Запись в стэк'),
        '0D00': ('PUSHF ', 'Запись флагов в стэк'),
        '0E00': ('SWAP', 'Обмен вершины стэка и аккумулятора')
    }
    return b.get(x)


def vet_com(x):
    v = {
        'F0': ('BEQ %s','Переход, если равенство'),
        'F1': ('BNE %s ', 'Переход, если неравенство'),
        'F2': ('BMI %s ', 'Переход, если минус'),
        'F3': ('BPL %s ', 'Переход, если плюс'),
        'F4': ('BLO/BCS %s ', 'Переход, если ниже/перенос'),
        'F5': ('BHIS/BCC %s ', 'Переход, если выше/нет переноса'),
        'F6': ('BVS %s ', 'Переход, если переполнение'),
        'F7': ('BVC %s ', 'Переход, если нет переполнения'),
        'F8': ('BLT %s ', 'Переход, если меньше'),
        'F9': ('BGE %s ', 'Переход, если больше или равно'),
        'CE': ('BR %s ', 'Безусловный переход (эквивалент JUMP c прямой относительной адресацией)'),
    }
    x_bin = hex_to_binary(x)
    offset = binary_to_signed_16(x_bin[8:16])
    if offset[0] != '-':
        m = 'IP+%s' % offset
    else:
        m = 'IP%s' % offset

    temp = v.get(x[0:2]) 
    return temp[0] % m, temp[1]


print("""
Будьте внимательны: парсер обрабатывает ВСЕ коды как команды, 
кроме тех, что он не может расшифровать (тогда он пишет, что это переменная или константа).
Однако некоторые коды на самом деле являются константами. Их нужно определять вручную.
(или пофиксить это и кинуть pull request на github.com/notgurev/bcomp-parser)

Напоминаю: парсер сделан только для ПРОВЕРКИ вашего решения. Не стоит на него полагаться.
""")
time.sleep(2)

with open('input.txt', 'r', encoding='utf-8') as lines:
    for c in lines:
        c = c.replace('\n', '').replace('+', '').strip()
        if len(c) != 4:  # не обрабатываем строки с длиной != 4
            print(c)
            continue
        output_line = c + ' | '
        try:
            if c[0] == "0":  # безадресная
                output_line += "{0[0]:<15} | {0[1]:<20}".format(bez_adr_com(c))
            elif c[0] == "F" or c[0:2] == "CE":  # ветвление
                output_line += "{0[0]:<15} | {0[1]:<20}".format(vet_com(c))
            elif c[0] == "1":  # ввода-вывода
                output_line += "Команды ввода-вывода не поддерживаются!"
            elif ("2" <= c[0] <= "9") or ("A" <= c[0] <= "E"):  # адресная
                output_line += "{0[0]:<15} | {0[1]:<20} | {0[2]: <20}".format(adr_com(c))
            else:
                output_line += "Переменная/ошибка"
        except:
            output_line += "Константа/ошибка"

        print(output_line, end='\n')
