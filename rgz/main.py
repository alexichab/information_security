import random
import os
import networkx as nx
import matplotlib.pyplot as plt
from collections import defaultdict

# Чтение графа из файла
def read_graph_from_file(filename, cycle_filename=None):
    with open(filename, 'r') as f:
        lines = f.readlines()
        # Читаем количество вершин и рёбер
        n, m = map(int, lines[0].split())
        graph = defaultdict(list)
        
        # Заполняем граф рёбрами
        for line in lines[1:m+1]:  # Используем строки из списка lines
            u, v = map(int, line.split())
            graph[u].append(v)
            graph[v].append(u)
        
        # Дополнительная информация (например, гамильтонов цикл)
        hamiltonian_cycle = None
        if cycle_filename and os.path.exists(cycle_filename):
            with open(cycle_filename, 'r') as cycle_file:
                hamiltonian_cycle = list(map(int, cycle_file.readline().split()))
        
        return graph, n, m, hamiltonian_cycle

# Перестановка вершин графа для создания изоморфного графа
def shuffle_graph(graph, n):
    permutation = list(range(n))
    random.shuffle(permutation)
    new_graph = {i: [] for i in range(n)}
    for u in range(n):
        for v in graph[u]:
            new_graph[permutation[u]].append(permutation[v])
    return new_graph, permutation

# Применение обратной перестановки
def apply_permutation(cycle, permutation):
    inverse_perm = {v: k for k, v in enumerate(permutation)}
    return [inverse_perm[v] for v in cycle]

# Генерация гамильтонова цикла
def generate_hamiltonian_cycle(n):
    cycle = list(range(n))
    random.shuffle(cycle)
    return cycle

# Проверка гамильтонова цикла в графе
def verify_hamiltonian_cycle(graph, cycle):
    n = len(graph)
    for i in range(n):
        u, v = cycle[i], cycle[(i + 1) % n]
        if v not in graph[u]:
            return False
    return True

# Протокол доказательства с нулевым знанием
def zero_knowledge_proof(graph, hamiltonian_cycle, n, rounds=3):
    for _ in range(rounds):
        # Шаг 1: Перемешать вершины графа
        shuffled_graph, permutation = shuffle_graph(graph, n)
        print("\nПеремешанный граф:")
        for i in range(n):
            print(f"{i}: {shuffled_graph[i]}")

        # Шаг 2: Проверяющий делает запрос
        challenge = random.choice(["isomorphism", "cycle"])
        
        if challenge == "isomorphism":
            # Запрос: Показать изоморфизм
            print("Проверяющий запросил изоморфизм.")
            print(f"Перестановка вершин: {permutation}")
        elif challenge == "cycle":
            # Запрос: Показать гамильтонов цикл
            print("Проверяющий запросил гамильтонов цикл.")
            new_cycle = apply_permutation(hamiltonian_cycle, permutation)
            if verify_hamiltonian_cycle(shuffled_graph, new_cycle):
                print(f"Гамильтонов цикл в новом графе: {new_cycle}")
            else:
                print("Ошибка: гамильтонов цикл неверен.")
                return False
        else:
            print("Ошибка протокола.")
            return False

    return True

# Визуализация графа текстовым выводом
def visualize_graph(graph, hamiltonian_cycle=None):
    # Печать рёбер графа
    print("\nГраф:")
    for node, neighbors in graph.items():
        print(f"Вершина {node}: {neighbors}")
    
    # Если есть гамильтонов цикл, выделяем его
    if hamiltonian_cycle:
        print("\nГамильтонов цикл:")
        cycle_edges = [(hamiltonian_cycle[i], hamiltonian_cycle[i+1]) for i in range(len(hamiltonian_cycle) - 1)]
        cycle_edges.append((hamiltonian_cycle[-1], hamiltonian_cycle[0]))  # Замкнуть цикл
        print("Рёбра гамильтонова цикла:")
        for edge in cycle_edges:
            print(edge)


# Тестовый пример
def main():
    filename = 'Path.txt' # Название файла с графом
    graph, n, m, hamiltonian_cycle = read_graph_from_file('Path.txt', 'hamiltonian_cycle.txt')
    
    if not hamiltonian_cycle:
        hamiltonian_cycle = generate_hamiltonian_cycle(n)
        print(f"Генерация гамильтонова цикла: {hamiltonian_cycle}")
    
    # Визуализация графа
    visualize_graph(graph, hamiltonian_cycle)

    # Запуск протокола доказательства
    result = zero_knowledge_proof(graph, hamiltonian_cycle, n)
    if result:
        print("Протокол завершён успешно. Доказательство корректно.")
    else:
        print("Ошибка протокола. Доказательство не удалось.")

if __name__ == "__main__":
    main()
