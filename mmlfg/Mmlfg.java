// Middle Multiplicative Lagged Fibonacci Generator
// This is free and unencumbered software released into the public domain.
public class Mmlfg {
    public int i = 14;
    public int j = 12;
    public final long[] s = new long[15];

    public Mmlfg(long seed) {
        for (int n = 0; n < 15; n++) {
            seed = seed*0x3243f6a8885a308dL + 1111111111111111111L;
            s[n] = seed ^ seed>>>31 | 1;
        }
    }

    public long next() {
        long lo = s[i] * s[j];
        long hi = Math.multiplyHigh(s[i], s[j]);
        hi += s[i]>>63 & s[j];
        hi += s[j]>>63 & s[i];
        s[i] = lo;
        i = i == 0 ? 14 : i-1;
        j = j == 0 ? 14 : j-1;
        return hi<<32 | lo>>>32;
    }

    public static void main(String[] args) {
        Mmlfg[] r = {new Mmlfg(0), new Mmlfg(1), new Mmlfg(2), new Mmlfg(3)};
        for (int i = 0; i < 40; i++) {
            System.out.printf("%016x %016x %016x %016x\n",
                              r[0].next(), r[1].next(),
                              r[2].next(), r[3].next());
        }
    }
}
