package org.example;
import com.fazecast.jSerialComm.SerialPort;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.concurrent.*;

import java.util.ArrayList;
import java.util.List;
public class Main {
    public static SerialPort detectHardwarePort() throws InterruptedException {
        SerialPort ports[] = SerialPort.getCommPorts();
        SerialPort comPort = null;
        for (SerialPort p : ports) {
            p.openPort();
            p.setComPortTimeouts(SerialPort.TIMEOUT_READ_BLOCKING, 1000, 0);
            // Set serial port parameters
            p.setBaudRate(115200);
            p.setNumDataBits(8);
            p.setNumStopBits(1);
            p.setParity(SerialPort.NO_PARITY);


            byte b[] = new byte[]{0};
            p.writeBytes(b, b.length);


            while (p.bytesAvailable() == 0)
                Thread.sleep(20);

            byte[] readBuffer = new byte[33];
            int numRead = p.readBytes(readBuffer, readBuffer.length);

            p.closePort();

            if (readBuffer[1] == 2 && readBuffer[32] == 1) {
                return p;
            }
        }
        return null;
    }
    public static void main(String[] args) {

        List<Callable<String>> callables = new ArrayList<>();
        callables.add(() -> {
            // Simulate long-running task
            Thread.sleep(10000);
            return "Result from task 1";  // Change to null to simulate returning null
        });
        callables.add(() -> {
            // Simulate long-running task
            Thread.sleep(50);
            return null; // This task returns null
        });
        callables.add(() -> {
            // Simulate long-running task
            Thread.sleep(500);
            return "Result from task 3";
        });

        // Create an ExecutorService
        ExecutorService executorService = Executors.newFixedThreadPool(3);

        try {
            String result = getFirstNonNullResult(executorService, callables);
            if (result != null) {
                System.out.println("First non-null result: " + result);
            } else {
                System.out.println("No non-null result found.");
            }
        } finally {
            // Shutdown the executor service
            executorService.shutdown();
        }
    }

    private static String getFirstNonNullResult(ExecutorService executorService, List<Callable<String>> callables) {
        try {
            List<Future<String>> futures = executorService.invokeAll(callables);

            for (Future<String> future : futures) {
                try {
                    String result = future.get();
                    if (result != null) {
                        // Cancel other futures
                        for (Future<String> f : futures) {
                            if (!f.isDone()) {
                                f.cancel(true);
                            }
                        }
                        return result;
                    }
                } catch (ExecutionException | InterruptedException e) {
                    e.printStackTrace();
                }
            }
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        return null;
    }


          /*
                try {

                    SerialPort comPort = detectHardwarePort();



                    if(comPort != null) {
                        for (int i = 0; true; i++) {
                            Thread.sleep(1000);
                            System.out.println("----------------------------");
                            System.out.println("Writing packet: " + i);
                            comPort.openPort();
                            comPort.setComPortTimeouts(SerialPort.TIMEOUT_READ_BLOCKING, 1000, 0);
                            // Set serial port parameters
                            comPort.setBaudRate(115200);
                            comPort.setNumDataBits(8);
                            comPort.setNumStopBits(1);
                            comPort.setParity(SerialPort.NO_PARITY);

                            // Write data to the serial port
                            String dataToSend = "Hello, Serial Port!";

                            //byte b[] = dataToSend.getBytes("utf-8");
                            byte b[] = new byte[]{2};
                            comPort.writeBytes(b, b.length);

                            System.out.println("Sent data(" + dataToSend + ")");

                            while (comPort.bytesAvailable() == 0)
                                Thread.sleep(20);

                            byte[] readBuffer = new byte[32];
                            int numRead = comPort.readBytes(readBuffer, readBuffer.length);
                            System.out.println(Arrays.toString(readBuffer));
                            //String result = new String(readBuffer, 0, numRead);
                            //System.out.println("Read " + numRead + " bytes. (" + result + ")");
                            comPort.closePort();
                            System.out.println("----------------------------");


                        }
                    }
                } catch (Exception e) {
                    System.out.println(e);
                }
*/

}