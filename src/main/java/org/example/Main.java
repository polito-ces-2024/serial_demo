package org.example;
import com.fazecast.jSerialComm.SerialPort;

import java.io.UnsupportedEncodingException;

public class Main {
    public static void main(String[] args) {
                try {
                    SerialPort comPort = SerialPort.getCommPorts()[0];

                    for(int i=0; true; i++) {
                        Thread.sleep(1000);
                        System.out.println("----------------------------");
                        System.out.println("Writing packet: " + i);
                        comPort.openPort();
                        comPort.setComPortTimeouts(SerialPort.TIMEOUT_READ_BLOCKING, 1000, 0);
                        // Set serial port parameters
                        comPort.setBaudRate(9600);
                        comPort.setNumDataBits(8);
                        comPort.setNumStopBits(1);
                        comPort.setParity(SerialPort.NO_PARITY);

                        // Write data to the serial port
                        String dataToSend = "Hello, Serial Port!";

                        byte b[] = dataToSend.getBytes("utf-8");
                        comPort.writeBytes(b, b.length);

                        System.out.println("Sent data(" + dataToSend + ")");

                        while (comPort.bytesAvailable() == 0)
                            Thread.sleep(20);

                        byte[] readBuffer = new byte[b.length];
                        int numRead = comPort.readBytes(readBuffer, readBuffer.length);

                        String result = new String(readBuffer, 0, numRead);
                        System.out.println("Read " + numRead + " bytes. (" + result + ")");
                        comPort.closePort();
                        System.out.println("----------------------------");


                    }
                } catch (InterruptedException | UnsupportedEncodingException e) {
                    throw new RuntimeException(e);
                }

    }
}