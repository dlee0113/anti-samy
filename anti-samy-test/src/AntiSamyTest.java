import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;

import org.owasp.validator.html.AntiSamy;
import org.owasp.validator.html.CleanResults;
import org.owasp.validator.html.Policy;
import org.owasp.validator.html.PolicyException;
import org.owasp.validator.html.ScanException;

public class AntiSamyTest {
	public static void main(String[] args) {
		try {
			ArrayList<String> dirtyInputs = readFile();
			
			for (String dirtyInput : dirtyInputs) {
				filter(dirtyInput);
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	private static String filter(String dirtyInput) {
		System.out.println("dirtyInput:  " + dirtyInput);
		
		String POLICY_FILE_LOCATION = "antisamy-anythinggoes-1.4.4.xml";
		String cleanOutput = "";
		
		try {
			Policy policy = Policy.getInstance(POLICY_FILE_LOCATION);
			AntiSamy as = new AntiSamy(); // Create AntiSamy object 
			CleanResults cr = as.scan(dirtyInput, policy, AntiSamy.SAX); // Scan dirtyInput 
			cleanOutput = cr.getCleanHTML();
			
			System.out.println("cleanOutput: " + cleanOutput); // Do something with your clean output!
			System.out.println();
		} catch (PolicyException e) {
			e.printStackTrace();
		} catch (ScanException e) {
			e.printStackTrace();
		}
		
		return cleanOutput;
	}
	
	private static ArrayList<String> readFile() throws IOException {
		File dir = new File(".");
		File fin = new File(dir.getCanonicalPath() + File.separator + "dirtyInputs.txt");		
		
		// Construct BufferedReader from FileReader
		BufferedReader br = new BufferedReader(new FileReader(fin));
		ArrayList<String> dirtyInputs = new ArrayList<String>();
		String line = null;
		while ((line = br.readLine()) != null) {
			dirtyInputs.add(line);
		}
	 
		br.close();
		
		return dirtyInputs;
	}
}
