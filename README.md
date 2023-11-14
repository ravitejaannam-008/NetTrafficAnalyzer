// Author : RAVITEJA
public class Calculator {
    private int result;

    public Calculator() {
        result = 0;
    } // Default Constructor

    // add
    public void add(int number) {
        result += number;
    }

    // subtract
    public void subtract(int number) {
        result -= number;
    }

    // multiply 
    public void multiply(int number1, int number2) {
        result = number1 * number2;
    }

    // divide 
    public void divide(int number1, int number2) {
        if (number2 != 0) {
            result = number1 / number2;
        } else {
            System.out.println("Cannot divide by zero");
            result = 0;
        }
    }

    // display the result
    public int getResult() {
        return result;
    }

    public static void main(String[] args) {
        // declare 2 numbers
        int num1 = 75, num2 = 25;
        // instantiate an object of type calculator
        Calculator myCalculator = new Calculator();
        
        System.out.println("Hello Professor, my name is Raviteja Annam");

        // add num1
        myCalculator.add(num1);
        System.out.println("The result for addition is: " + myCalculator.getResult());

        // subtract num2
        myCalculator.subtract(num2);
        System.out.println("The result for subtraction is: " + myCalculator.getResult());

        // multiply num1 and num2
        myCalculator.multiply(num1, num2);
        System.out.println("The result for multiplication is: " + myCalculator.getResult());


        // divide 
        myCalculator.divide(num1, num2);
        System.out.println("The result for division is: " + myCalculator.getResult());
    }
}
