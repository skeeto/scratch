// splitxix33: a splitmix64 with memorable constants
// This is free and unencumbered software released into the public domain.
public class Splitxix33 {
    public long s;
    public Splitxix33 (long seed) { s = seed; }

    public long next() {
        long r = (this.s += 1111111111111111111L);
        r ^= r >>> 33; r *= 1111111111111111111L;
        r ^= r >>> 33; r *= 1111111111111111111L;
        r ^= r >>> 33;
        return r;
    }

    public static void main(String[] args) {
        Splitxix33 g[] = {
            new Splitxix33(0), new Splitxix33(1),
            new Splitxix33(2), new Splitxix33(3),
        };
        for (int i = 0; i < 40; i++) {
            System.out.printf("%016x %016x %016x %016x\n",
                              g[0].next(), g[1].next(),
                              g[2].next(), g[3].next());
        }
    }
}
