# Schröder numbers
# https://en.wikipedia.org/wiki/Schr%C3%B6der_number
# This is free and unencumbered software released into the public domain.

class Schröder(dict):
    def __init__(self):
        self[0] = 1
        self[1] = 2

    def __call__(self, n):
        try:
            return self[n]
        except KeyError:
            n1 = self(n - 1)
            n2 = self(n - 2)
            r  = (6*n - 3)*n1//(n + 1) - (n - 2)*n2//(n + 1)
            self[n] = r
            return r

f = Schröder()
for i in range(100):
    print(i+1, f(i))
