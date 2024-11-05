import hashlib as hl
import os
import random
import sys
import numpy as np
import openpyxl
import scipy.stats as sp
from matplotlib import pyplot as plt
from typing import List, Tuple
from openpyxl.styles import Font


#   <---------------PREIMAGE ATTACK--------->
def preimage_attack(alphabet, start_message, output_file, attack=1, logs=True, output=True):
    pra_char = 124  # 128 - 4
    pra_bytes = 62  # 64 - 2
    msg_len = len(start_message)

    with open(output_file, 'w') as log_file:
        preimage_hash = hl.sha512(start_message.encode())
        preimage_hash_bytes = preimage_hash.digest()[pra_bytes:]
        preimage_hash_hex = preimage_hash.hexdigest()

        if logs:
            log_file.write(f"{start_message:{msg_len}s}: "
                           f"{preimage_hash_hex[:pra_char]}\t{preimage_hash_hex[pra_char:]}\n")
        if output:
            print(f"Preimage attack {2 if attack == 2 else 1}\nBase message is: {start_message}\n"
                  f"{start_message:{msg_len}s}: {preimage_hash_hex[:pra_char]}\t{preimage_hash_hex[pra_char:]}")

        iteration = 0
        for i in range(1, sys.maxsize):
            msg = modify_message(start_message, alphabet) if attack == 2 else f"{start_message}{i}"
            msg_hash = hl.sha512(msg.encode())
            msg_hash_hex = msg_hash.hexdigest()

            if logs:
                log_file.write(f"{msg:{msg_len}s}: {msg_hash_hex[:pra_char]}\t{msg_hash_hex[pra_char:]}")
            if msg_hash.digest()[pra_bytes:] == preimage_hash_bytes:
                if attack == 2 and msg == start_message:
                    if logs:
                        log_file.write('\n')
                    continue
                if output:
                    write_preimage(log_file, i, msg, msg_hash_hex, msg_len, pra_char)
                iteration = i
                break
            else:
                if logs:
                    log_file.write('\n')

    return iteration


def write_preimage(log_file, i, msg, msg_hash_hex, msg_len, pra_char):
    log_file.write(f"\nSecond preimage found on attempt {i}!")
    print(f"{msg:{msg_len}s}: {msg_hash_hex[:pra_char]}\t{msg_hash_hex[pra_char:]}\n"
          f"Second preimage found on attempt {i}!\n")


#   <---------------BIRTHDAY ATTACK--------->
def birthday_attack(alphabet, start_message, output_file, attack=1, logs=True, output=True):
    bra_char = 120  # 128 - 8
    bra_bytes = 60  # 64 - 4
    msg_len = len(start_message)

    with open(output_file, 'w') as log_file:
        birthday_hash = hl.sha512(start_message.encode())
        birthday_hash_hex = birthday_hash.hexdigest()

        if logs:
            log_file.write(f"{start_message:{msg_len}s}: "
                           f"{birthday_hash_hex[:bra_char]}\t{birthday_hash_hex[bra_char:]}\n")
        if output:
            print(f"Birthday attack {2 if attack == 2 else 1}\nBase message is: {start_message}\n"
                  f"{start_message:{msg_len}s}: {birthday_hash_hex[:bra_char]}\t{birthday_hash_hex[bra_char:]}")

        prev_dict = {birthday_hash.digest()[bra_bytes:]: start_message}
        iteration = 0
        for i in range(1, sys.maxsize):
            msg = modify_message(start_message, alphabet) if attack == 2 else f"{start_message}{i}"

            msg_hash = hl.sha512(msg.encode())
            msg_hash_hex = msg_hash.hexdigest()
            msg_hash_bytes = msg_hash.digest()[bra_bytes:]

            if msg_hash_bytes in prev_dict:
                collision = prev_dict[msg_hash_bytes]
                collision_hash = hl.sha512(collision.encode()).hexdigest()
                if output:
                    write_collision(log_file, i, msg, collision, msg_hash_hex, collision_hash, msg_len, bra_char)
                iteration = i
                break
            else:
                prev_dict[msg_hash_bytes] = msg
                if logs:
                    log_file.write(f"{msg:{msg_len}s}: {msg_hash_hex[:bra_char]}\t{msg_hash_hex[bra_char:]}\n")

    return iteration


def write_collision(log_file, i, msg, col, msg_hash_hex, col_hash, msg_len, bra_char):
    log_file.write(f"\nMessage: {msg:{msg_len}s}: {msg_hash_hex[:bra_char]}\t{msg_hash_hex[bra_char:]}\n"
                   f"Collision: {col:{msg_len}s}: {col_hash[:bra_char]}\t{col_hash[bra_char:]}\n"
                   f"Collision found in {i} iterations!\n")
    print(f"Message: {msg:{msg_len}s}: {msg_hash_hex[:bra_char]}\t{msg_hash_hex[bra_char:]}\n"
          f"Collision: {col:{msg_len}s}: {col_hash[:bra_char]}\t{col_hash[bra_char:]}\n"
          f"Collision found in {i} iterations!\n")


#   <---------------ADDITIONAL FUNCTION--------->
def modify_message(message, alphabet, replacement_chance=0.2, addition_chance=0.2):
    modified_message = list(message)
    length = len(modified_message)

    for i in range(length):
        if random.random() < replacement_chance:
            modified_message[i] = random.choice(alphabet)

    i = 0
    while i < len(modified_message):
        if random.random() < addition_chance:
            modified_message.insert(i, random.choice(alphabet))

        i += 1

    return ''.join(modified_message)


#   <---------------FUNCTION FOR BOTH ATTACK--------->
def multy_run_of_attack(output_file, attack, num_attack, alphabet, base_msg):
    stats: List[Tuple[str, int]] = []

    for _ in range(120):
        msg = modify_message(base_msg, alphabet)
        attack_result = birthday_attack(alphabet, msg, output_file, num_attack, False, False) \
            if attack == 2 else preimage_attack(alphabet, msg, output_file, num_attack, False, False)
        stats.append((msg, attack_result))

    return stats


def calculation_static_values(stats, gamma=0.95):
    data = [count for _, count in stats]
    sum_itr = np.sum(data)
    mean_val = np.mean(data)
    variance = np.var(data)
    std_dev = np.sqrt(variance)

    q = 1 - ((1 - gamma) / 2)
    scale_t = sp.t.ppf(q, 120 - 1)
    confidence_interval = (mean_val - (scale_t * std_dev / np.sqrt(120)),
                           mean_val + (scale_t * std_dev / np.sqrt(120)))

    print(f"Sum of iterations: {sum_itr}")
    print(f"Mean: {mean_val}")
    print(f"Variance: {variance} -> Standart deviance: {std_dev}")
    print(f"Confidence interval: {confidence_interval}")


#   <---------------VISUALIZATION--------->
def excel_create(data, file_name):
    wb = openpyxl.Workbook()
    ws = wb.active

    headers = ["Start message", "Iteration count"]
    ws.append(headers)
    for cell in ws[1]:
        cell.font = Font(bold=True)

    for start_message, iteration_count in data:
        ws.append([start_message, iteration_count])

    for column in ws.columns:
        max_length = 0
        column = [cell for cell in column]
        for cell in column:
            try:
                if len(str(cell.value)) > max_length:
                    max_length = len(str(cell.value))
            except:
                pass
        adjusted_width = (max_length + 2)
        ws.column_dimensions[column[0].column_letter].width = adjusted_width

    reports_dir = 'reports'
    os.makedirs(reports_dir, exist_ok=True)
    report_filepath = os.path.join(reports_dir, file_name)
    wb.save(report_filepath)


def create_hist(data_array, attack):
    plt.figure(figsize=(15, 6))
    counts, bins, _ = plt.hist(data_array, bins=20, edgecolor='black')

    plt.title(f"Iterations Distribution for Attack {attack}")
    plt.grid(True)
    plt.yticks(range(int(np.max(counts)) + 1))
    plt.xlim([np.min(data_array) - 1000, np.max(data_array) + 1000])
    plt.xticks(bins, rotation=45)

    plt.savefig(f'hist{attack}.png')
    plt.show(block=False)


def main():
    name_msg = "BalatskaViktoriaVitaliivna"
    alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!"#$%&\'()*+,-./:;<=>?@[]^_`{|}\\~'

    attack = int(input(f'Choose type of attack:\n\t1. Preimage attack\n\t2. Birthday attack\n'))
    num_of_attack = int(input(f'Choose number of attack:\n\t1. First number of attack\n\t2. Second number of attack\n'))
    multiple = int(input(f'Choose type of attack:\n\t1. Single attack\n\t2. Multiple attack\n'))

    if (attack != 1 and attack != 2) or (num_of_attack != 1 and num_of_attack != 2) or (
            multiple != 1 and multiple != 2):
        exit('Invalid input for some variant')

    if attack == 1:
        if multiple == 2:
            stats = multy_run_of_attack(
                f'preimage_attack_1.{num_of_attack}_stats.txt', 1, num_of_attack, alphabet, name_msg)
            excel_create(stats, f'preimage_attack_1.{num_of_attack}_stats.xlsx')
            calculation_static_values(stats)
            create_hist([iteration[1] for iteration in stats], f'1.{num_of_attack}')
        else:
            preimage_attack(alphabet, name_msg, f'preimage_attack_{num_of_attack}.txt', num_of_attack)
    else:
        if multiple == 2:
            stats = multy_run_of_attack(
                f'birthday_attack_2.{num_of_attack}_stats.txt', 2, num_of_attack, alphabet, name_msg)
            excel_create(stats, f'birthday_attack_2.{num_of_attack}_stats.xlsx')
            calculation_static_values(stats)
            create_hist([iteration[1] for iteration in stats], f'2.{num_of_attack}')
        else:
            birthday_attack(alphabet, modify_message(name_msg, alphabet),
                            f'birthday_attack_{num_of_attack}.txt', num_of_attack)


if __name__ == '__main__':
    main()
