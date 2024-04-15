# Trace_route


Проект является ускоренным и упрощенным вариантом ```tracert```. 

Утилита tracert в системе Windows используется для
определения маршрутов следования данных в сетях TCP/IP.

Чтобы собрать проект и получить исполняемые файлы основной программы и тестов,
используйте инструменты системы автоматизации сборки ```CMake```. 

Чтобы узнать, установлена ли система CMake на вашем устройстве, откройте командную строку (Win + R -> cmd) и введите:
```
cmake --version
```
Если CMake установлена, вывод будет похожим на этот:
```
cmake version 3.29.2

CMake suite maintained and supported by Kitware (kitware.com/cmake).
```
В противном случае, CMake необходимо скачать и установить.

1. Ссылка оффициального сайта: https://cmake.org/download/

    Выберите подходящий для вас вариант (желательно самую позднюю версию).
2. Скачайте и установите 

   (во вкладке опций для установки выберите "Добавить CMake в систему PATH для всех пользователей").
3. После установки система CMake должна быть доступна. 

   Чтобы убедиться, повторно введите команду ```cmake --version```.

В командной строке перейдите в папку проекта ```Trace_route```.

Для запуска тестов (и успешной сборки проекта) необходимо, находясь в папке Trace_route, склонировать GitHub-репозиторий googletest, используя команду:
```
git clone http://github.com/google/googletest.git
```
В папке Trace_route создайте внутреннюю папку ```build```с помощью команды:
```
mkdir build
```
Перейдите в папку build, введя команду:
```
cd build
```

В папке Trace_route/build ведите команду:
```
cmake ..
```
Дождитесь завершения выполнения команды, затем введите команду:
```
cmake --build .
```
Процесс выполнения может занять некоторое время.

Далее перейдите во внутреннюю папку ```Debug``` (Trace_route/build/Debug), созданную с помощью последней команды.

В этой папке и находятся исполняемые файлы программы (и тестов).  

Для того, чтобы посмотреть содержимое папки Debug, введите команду:
```
dir
```
Результат будет примерно таким: 
```

15.04.2024  20:39    <DIR>          .
15.04.2024  20:39    <DIR>          ..
15.04.2024  22:02         1 269 760 test_traceroute.exe
15.04.2024  22:02        11 546 624 test_traceroute.pdb
15.04.2024  20:39           143 360 traceroute.exe
15.04.2024  20:39         1 773 568 traceroute.pdb
               4 файлов     14 733 312 байт
               2 папок  68 970 733 568 байт свободно

```
Исполняемый файл программы: ```traceroute.exe```.

Исполняемый файл тестов: ```test_traceroute.exe```.

Чтобы выполнить запустить файл тестов, введите имя исполняемого файла:
```
test_traceroute.exe
```
Чтобы запустить файл основной программы, введите имя файла и доменное имя узла назначения
```
traceroute.exe google.com
```
Или имя файла и адрес узла назначения
```
traceroute.exe 142.250.184.206
```
Для отображения адресов промежуточных маршрутизаторов необходимо отключить брандмауэр и защиту сети. Это связано с ограничением прав программы.

Дополнительные флаги команды tracert не реализованы.