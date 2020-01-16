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

    public static void main (String[] args) {
        // Génération des clefs. A pour Alice, B pour Bob.
        Paillier paillier = new Paillier();
        ArrayList<BigInteger> pksk = paillier.keyGen();
        BigInteger pkB = pksk.get(0);
        BigInteger skB = pksk.get(1);
        BigInteger pk2B = pkB.multiply(pkB);

        // Génération de x et de y puis encryption par Alice
        int l = pkB.bitLength();
        BigInteger xA = new BigInteger(l+100, paillier.rnd);
        BigInteger yA = new BigInteger(l+100, paillier.rnd);
        xA = xA.mod(pkB);
        yA = yA.mod(pkB);
        BigInteger XA = paillier.encrypt(pkB, xA);
        BigInteger YA = paillier.encrypt(pkB, yA);

        // Génération et encryption des masques s et t par Alice
        BigInteger sA = new BigInteger(l+100, paillier.rnd);
        sA = sA.mod(pkB);
        BigInteger tA = new BigInteger(l+100, paillier.rnd);
        tA = tA.mod(pkB);
        BigInteger SA = paillier.encrypt(pkB, sA);
        BigInteger TA = paillier.encrypt(pkB, tA);

        // Application des masques par Alice
        BigInteger UA = XA.multiply(SA).mod(pk2B);
        BigInteger VA = YA.multiply(TA).mod(pk2B);


        // #1 *** ENVOIE DE UA ET VA A BOB *** //


        // Décryption de UA et VA par puis encrypion du produit par Bob
        BigInteger uB = paillier.decrypt(pkB, skB, UA);
        BigInteger vB = paillier.decrypt(pkB, skB, VA);
        BigInteger WB = paillier.encrypt(pkB, uB.multiply(vB));


        // #2 *** ENVOIE DE WB A ALICE *** //


        // Déduction de l'encryption du produit de x y par Alice
        BigInteger TXA = paillier.encrypt(pkB, xA.multiply(tA));
        BigInteger SYA = paillier.encrypt(pkB, yA.multiply(sA));
        BigInteger STA = paillier.encrypt(pkB, sA.multiply(tA));
        //BigInteger XYA = WB.subtract(TXA).mod(pk2B).subtract(SYA).mod(pk2B).subtract(STA).mod(pk2B); // mod ?
        BigInteger XYA = WB.multiply(XA.modPow(tA.negate(), pk2B));
        XYA = XYA.multiply(YA.modPow(sA.negate(), pk2B));
        XYA = XYA.multiply(STA.negate());
        XYA = XYA.mod(pk2B);

        // Génération et encryption de delta (d), puis calcul et encryption de pi (p) par Bob
        BigInteger dB = new BigInteger(l-2, paillier.rnd);
        BigInteger DB = paillier.encrypt(pkB, dB);
        BigInteger PB = paillier.encrypt(pkB, dB.multiply(vB).mod(pkB));


        // #3 *** ENVOIE DE D ET DE P A ALICE ***


        // Génération et encryption de e par Alice
        BigInteger eA = new BigInteger(l-2, paillier.rnd);
        BigInteger EA = paillier.encrypt(pkB, eA);


        // #4 *** ENVOIE DE EA A BOB ***


        //Decryption de E puis calcul des preuves par Bob
        BigInteger eB = paillier.decrypt(pkB, skB, EA);
        List<BigInteger> arB = paillier.decryptPlus(pkB, skB, UA.modPow(eB, pk2B).multiply(DB).mod(pk2B));
        List<BigInteger> aarrB = paillier.decryptPlus(pkB, skB, VA.modPow(arB.get(0), pk2B).multiply(PB.modPow(BigInteger.ONE.negate(), pk2B)).mod(pk2B).multiply(WB.modPow(eB.negate(), pk2B)).mod(pk2B)); // negate().mod ?


        // #5 *** ENVOIE DE arB ET DE aarrB A ALICE ***


        //Vérification des preuves par Alice
        if (!aarrB.get(0).equals(BigInteger.ZERO)) {
            System.out.println("a' différent de zéro");
        } else {
            BigInteger t11 = BigInteger.ONE.add(arB.get(0).multiply(pkB).mod(pk2B)).multiply(arB.get(1).modPow(pkB, pk2B)).mod(pk2B);
            BigInteger t12 = UA.modPow(eA, pk2B).multiply(DB).mod(pk2B);
            if (!t11.equals(t12)) {
                System.out.println(" preuve (1+an)r^n = U^eD non vérifié");
            } else {
                BigInteger t21 = BigInteger.ONE.add(aarrB.get(0).multiply(pkB).mod(pk2B)).multiply(aarrB.get(1).modPow(pkB, pk2B)).mod(pk2B);
                BigInteger t22 = VA.modPow(arB.get(0), pk2B).multiply(PB.modPow(BigInteger.ONE.negate(), pk2B)).mod(pk2B).multiply(WB.modPow(eA.negate(), pk2B)).mod(pk2B);
                if (!t21.equals(t22)){
                    System.out.println(" preuve (1+a'n)r'^n = V^aP^-1W^-e non vérifié");
                } else {
                    System.out.println("Le protocol est validé");
                }
            }
        }

        // test du produit
        BigInteger xy = xA.multiply(yA).mod(pkB); //pkb tancrede
        BigInteger decryptXYA = paillier.decrypt(pkB, skB, XYA).mod(pkB);//retirer le mod
        if (decryptXYA.equals(xy)) {
            System.out.println("Produit validé");
        } else {
            System.out.println("Produit non validé");
        }
    }
}