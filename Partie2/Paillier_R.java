import java.awt.*;
import java.math.BigInteger;
import java.util.*;

public class Paillier_R {
    private Random rnd;
    private BigInteger p;
    private BigInteger q;
    private BigInteger n;
    private BigInteger phi;
    private BigInteger r;

    public Paillier_R(){
        rnd = new Random();
    }

    public ArrayList<BigInteger> keyGen(BigInteger lambda) {
        ArrayList<BigInteger> pksk = new ArrayList<>();
        p = new BigInteger(512, 1, rnd);
        q = new BigInteger(512, 1, rnd);
        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        n = p.multiply(q);

        pksk.add(n);
        pksk.add(n.modInverse(phi));
        return pksk;
    }

    public BigInteger encrypt(BigInteger pk, BigInteger m){
        r =  new BigInteger(pk.bitLength()-2, rnd);
        BigInteger a = (m.multiply(pk).add(BigInteger.ONE)).mod(pk.pow(2));
        BigInteger b = r.modPow(pk, pk.pow(2));

        return  (a.multiply(b)).mod(pk.pow(2)) ;
    }

    public BigInteger decrypt(BigInteger pk, BigInteger sk, BigInteger c){
        r = c.mod(pk).modPow(sk, pk.pow(2));

        BigInteger m = c.multiply(r.modPow(pk.negate(),pk.pow(2) )).subtract(BigInteger.ONE).mod(pk.pow(2));
        return m.divide(pk);
    }

    public static void main (String[] args) {
        Paillier_R paillier = new Paillier_R();

        // générartion de la clé secrète
        ArrayList<BigInteger> pksk = paillier.keyGen(BigInteger.ZERO);
        BigInteger pk = pksk.get(0);
        BigInteger sk = pksk.get(1);
        int l = pk.bitLength();

        // bob a maintenant la clé secrète pk et va encrypter x
        // ici on déclare 0 et 1
        BigInteger zero = new BigInteger(String.valueOf(0));
        BigInteger one = new BigInteger(String.valueOf(1));

        // On a la x non encrypté que bob va encrypter
        ArrayList<BigInteger> x = new ArrayList<>();
        x.add(one);
        x.add(zero);
        x.add(one);
        x.add(zero);
        x.add(one);
        x.add(zero);

        // On a le x encrypté que bob va envoyer a alice
        ArrayList<BigInteger> encryptedX = new ArrayList<>();
        for(int i=0;i<x.size();i++) {
            encryptedX.add(paillier.encrypt(pk,x.get(i)));
        }

        // bob envoie a alice

        // déclaration de la 3-DNF chez alice
        ArrayList<ArrayList<Point>> indiceDNF = new ArrayList<>();

        ArrayList<Point> t = new ArrayList<>();
        t.add(new Point(1,0));
        t.add(new Point(3,0));
        t.add(new Point(5,0));
        indiceDNF.add(t);

        ArrayList<Point> t1 = new ArrayList<>();
        t1.add(new Point(1,0));
        t1.add(new Point(2,0));
        t1.add(new Point(3,0));
        indiceDNF.add(t1);

        // on crée le -3 encrypté
        BigInteger moins3 = new BigInteger(String.valueOf(-3));
        BigInteger moins3encrypted = paillier.encrypt(pk,moins3);

        // j < 3 car 3-DNF
        ArrayList<BigInteger> result = new ArrayList<>();
        for(int i=0;i<indiceDNF.size();i++) {
            BigInteger resultOfMultiplication = one;
            BigInteger randGenere = new BigInteger(l-2, paillier.rnd);

            for(int j=0;j<3;j++) {
                if(indiceDNF.get(i).get(j).y == 0) {
                    resultOfMultiplication = resultOfMultiplication.multiply(encryptedX.get(indiceDNF.get(i).get(j).x - 1));
                    resultOfMultiplication = resultOfMultiplication.mod(pk.pow(2));
                } else {
                    resultOfMultiplication = resultOfMultiplication.multiply(encryptedX.get(1 - Math.abs(indiceDNF.get(i).get(j).x - 1)));
                    resultOfMultiplication = resultOfMultiplication.mod(pk.pow(2));
                }
            }

            // On a la valeur encrypté qui contient la somme des valeurs décryptées -3
            resultOfMultiplication = resultOfMultiplication.multiply(moins3encrypted);
            resultOfMultiplication = resultOfMultiplication.mod(pk.pow(2));

            resultOfMultiplication = resultOfMultiplication.modPow(randGenere, pk.pow(2));

            result.add(resultOfMultiplication);
        }

        Collections.shuffle(result);

        Random random = new Random();
        int randomToAdd = random.nextInt(100) + 1;

        BigInteger m;
        for(int i=0;i<randomToAdd;i++) {
            m = new BigInteger(l-2, paillier.rnd);
            result.add(m.add(BigInteger.ONE));
        }

        boolean rep = false;

        // chez bob, on a le résultat suivant
        for(int i=0;i<result.size();i++) {
            // on décrypte
            BigInteger dm = paillier.decrypt(pk, sk, result.get(i));
            //System.out.println("Val décryptée : " + dm);
            if(dm.equals(BigInteger.ZERO)) {
                rep = true;
                break;
            }
        }

        System.out.println("La réponse est : " + rep);
    }

}
