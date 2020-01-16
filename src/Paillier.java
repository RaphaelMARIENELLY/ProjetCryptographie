package Partie1.src;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class Paillier {

    private Random rnd;
    private BigInteger r;

    public Paillier(){
        rnd = new Random();
    }

    public ArrayList<BigInteger> keyGen() {
        ArrayList<BigInteger> pksk = new ArrayList<>();
        BigInteger p = new BigInteger(512, 1, rnd);
        BigInteger q = new BigInteger(512, 1, rnd);
        BigInteger n = p.multiply(q);
        pksk.add(n);
        pksk.add(n.modInverse(p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE))));
        return pksk;
    }

    public BigInteger encrypt(BigInteger pk, BigInteger m) {
        r =  new BigInteger(pk.bitLength()-2, rnd);
        BigInteger pk2 = pk.pow(2);
        BigInteger a = (m.multiply(pk).add(BigInteger.ONE)).mod(pk2);
        BigInteger b = r.modPow(pk, pk2);
        return a.multiply(b).mod(pk2);
    }

    public List<BigInteger> encryptPlus(BigInteger pk, BigInteger m) {
        List<BigInteger> emr = new ArrayList<>();
        r =  new BigInteger(pk.bitLength(), rnd);
        r = r.mod(pk);
        BigInteger pk2 = pk.pow(2);
        BigInteger a = (m.multiply(pk).add(BigInteger.ONE)).mod(pk2);
        BigInteger b = r.modPow(pk, pk2);
        emr.add((a.multiply(b)).mod(pk2));
        emr.add(r);
        return  emr;
    }

    public List<BigInteger> decryptPlus(BigInteger pk, BigInteger sk, BigInteger em) {
        List<BigInteger> dmr = new ArrayList<>();
        BigInteger pk2 = pk.pow(2);
        r = em.mod(pk).modPow(sk, pk2);
        BigInteger m = em.multiply(r.modPow(pk.negate(), pk2)).subtract(BigInteger.ONE).mod(pk2);
        dmr.add(m.divide(pk).mod(pk2));
        dmr.add(r);
        return dmr;
    }

    public BigInteger decrypt(BigInteger pk, BigInteger sk, BigInteger em) {
        BigInteger pk2 = pk.pow(2);
        r = em.mod(pk).modPow(sk, pk2);
        BigInteger m = em.multiply(r.modPow(pk.negate(),pk2)).subtract(BigInteger.ONE).mod(pk2);
        return m.divide(pk).mod(pk2);
    }


}