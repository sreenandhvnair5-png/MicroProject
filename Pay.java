import java.util.Scanner;

class Pay {
    int age;
    float basic;
    float newB;

    // Constructor (matches class name)
    Pay(int age, int basic) {
        this.age = age;
        this.basic = basic;
    }

    
    void calculate() {
        float p;
        if (age > 56) {
            p = 0.20f;
        } else if (age >= 45 && age <= 56) {
            p = 0.15f;
        } else {
            p = 0.10f;
        }
        
        
        calculate(p); 
    }

    
    void calculate(float percentage) {
        newB = basic + (basic * percentage);
    }

    void display() {
        System.out.println("New Basic pay is : " + newB);
    }

    public static void main(String[] args) {
        Scanner in = new Scanner(System.in);

        System.out.println("Enter age and Basic pay:");
        int x = in.nextInt();
        int y = in.nextInt();

        Pay c = new Pay(x, y);

        c.calculate(); 
        c.display();

        in.close();
    }
}