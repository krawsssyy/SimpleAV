package ism.assign02;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class avapp {
	
	private class Pair<T1, T2> {
		public final T1 first;
		public final T2 second;
		public Pair(T1 a, T2 b) {
			this.first = a;
			this.second = b;
		}
	}

	public static void main(String[] args) throws IOException, InvalidKeyException, NoSuchAlgorithmException {
		if (args.length != 4) {
			System.out.println("Usage:Java.exe avapp.java scan|check hmacPwd rootDir hmacFile\nFor scan, the file may not exist");
			return;
		}
		
		if(!(args[0].equals("scan")) && !(args[0].equals("check"))) {
			System.out.println("Usage:Java.exe avapp.java scan|check hmacPwd rootDir hmacFile\nFirst argument must be either scan or check");
			return;
		}
		
		if(!((new File(args[2])).exists())) {
			System.out.println("Root directory must exist");
			return;
		}
		
		if(args[0].equals("check") && ((new File(args[3])).length() == 0)) {
			System.out.println("When using check, the HMAC file needs to exist. Create it before with scan");
			return;
		}
		
		
		String hmacPwd = args[1];
		ArrayList<File> scanList = new ArrayList<File>();
		File rootDir = new File(args[2]);
		File hmacFile = new File(args[3]);
		ArrayList<avapp.Pair<File, String>> hmacList = new ArrayList<avapp.Pair<File, String>>();
		if(!hmacFile.exists()) {
			hmacFile.createNewFile();
		}
		
		if(args[0].equals("scan")) {
			traverseDirs(rootDir, scanList);
			for(File f : scanList) {
				hmacList.add(new avapp().new Pair<File, String>(f, new String(Base64.getEncoder().encode(getHMAC(f.getAbsolutePath(), hmacPwd, "HMACSHA256")))));
			}
			FileWriter fw = new FileWriter(hmacFile);
			PrintWriter pw = new PrintWriter(fw);
			for(avapp.Pair<File, String> p : hmacList) {
				pw.write(p.first + "," + p.second + "\n");
			}
			fw.close();
			return;	
		}
		else {
			FileReader fr = new FileReader(hmacFile);
			BufferedReader br = new BufferedReader(fr);
			String line = br.readLine();
			while(line != null) {
				hmacList.add(new avapp().new Pair<File, String>(new File(line.split(",")[0]), line.split(",")[1].strip()));
				line = br.readLine();
			}
			fr.close();
			traverseDirs(rootDir, scanList);
			ArrayList<avapp.Pair<File, String>> hmacListCheck = new ArrayList<avapp.Pair<File, String>>();
			for(File f : scanList) {
				hmacListCheck.add(new avapp().new Pair<File, String>(f, new String(Base64.getEncoder().encode(getHMAC(f.getAbsolutePath(), hmacPwd, "HMACSHA256")))));
			}
			
			File report = new File("results_" + LocalDateTime.now().toString().split("\\.")[0].replace(':', '-') + ".log");
			report.createNewFile();
			FileWriter fw = new FileWriter(report);
			PrintWriter pw = new PrintWriter(fw);
			for(avapp.Pair<File, String> p : hmacListCheck) {
				if(!inList(p.first, hmacList)) {
					pw.write(p.first.getAbsolutePath() + " NEW\n");
					continue;
				}
				if(checkHMAC(p, hmacList)) {
					pw.write(p.first.getAbsolutePath() + " OK\n");
				}
				else {
					pw.write(p.first.getAbsolutePath() + " CORRUPTED\n");
				}
			}
			for(avapp.Pair<File, String> p : hmacList) {
				if(!inList(p.first, hmacListCheck)) {
					pw.write(p.first.getAbsolutePath() + " DELETED\n");
					continue;
				}
			}
			fw.close();
			return;
		}
	}
	
	private static void traverseDirs(File root, ArrayList<File> scanList) {
		for(File f : root.listFiles()) {
			if(f.isDirectory()) {
				traverseDirs(f, scanList);
			}
			else {
				scanList.add(f);
			}
		}
	}
	
	private static byte[] getHMAC(String fileName, String key, String algorithm) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
		File file = new File(fileName);
		FileInputStream fis = new FileInputStream(file);
		BufferedInputStream bis = new BufferedInputStream(fis);
		byte[] buffer = new byte[16];
		int noBytes = 0;
		Mac mac = Mac.getInstance(algorithm);
		mac.init(new SecretKeySpec(key.getBytes(), algorithm));
		while(noBytes != -1) {
			noBytes = bis.read(buffer);
			if(noBytes != -1)
				mac.update(buffer,0,noBytes);
		}
		fis.close();
		return mac.doFinal();	
	}
	
	private static boolean inList(File file, ArrayList<avapp.Pair<File, String>> list) {
		for (avapp.Pair<File, String> p : list) {
			if (p.first.getAbsolutePath().equals(file.getAbsolutePath())) {
				return true;
			}
		}
		return false;
	}
	
	private static boolean checkHMAC(avapp.Pair<File, String> obj, ArrayList<avapp.Pair<File, String>> list) {
		for (avapp.Pair<File, String> p : list) {
			if (p.first.getAbsolutePath().equals(obj.first.getAbsolutePath())) {
				if(p.second.equals(obj.second)) {
					return true;
				}
				break;
			}
		}
		return false;
	}
	
}