state = [
    [206, 243, 61, 34],
    [171, 11, 93, 31],
    [16, 200, 91, 108],
    [150, 3, 194, 51],
]

round_key = [
    [173, 129, 68, 82],
    [223, 100, 38, 109],
    [32, 189, 53, 8],
    [253, 48, 187, 78],
]

def matrix2bytes(matrix):
    return "".join([chr(n) for lst in matrix for n in lst])

def add_round_key(s, k):
    return [[x^y for x,y in zip(sum(s,[]), sum(k,[]))][i:i+4] for i in range(0,16,4)]


print(matrix2bytes(add_round_key(state, round_key)))