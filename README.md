# bcomp-decoder
Расшифровщик команд БЭВМ. Переводит код команды в мнемонику (пока что криво для адресных команд) и наименование (информация из презентаций).

Ошибки не обрабатываются. Каждая строка должна содержать ТОЛЬКО четырехзначное шестнадцатеричное число. 

Каждое такое число программа распознает как команду, а не данные (переменные и тд).

Команды ввода-вывода не поддерживаются.

Стек/подпрограммы/прерывание не поддерживаются.

TODO: 
1. Нормальное форматирование, красивый вывод
2. Все остальное для следующих лаб.