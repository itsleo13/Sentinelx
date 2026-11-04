numbers = [10,23,45,67,34]
smallest = numbers[0]

for num in numbers:
    if num < smallest:
        smallest = num

print("Smallest =", smallest)