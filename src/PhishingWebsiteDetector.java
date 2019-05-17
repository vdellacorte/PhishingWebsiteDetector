import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Random;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.HttpsURLConnection;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;

import org.apache.commons.net.whois.WhoisClient;
import org.json.JSONObject;
import org.jsoup.Connection;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.omg.CosNaming.IstringHelper;

import javafx.application.Application;
import javafx.event.ActionEvent;
import javafx.geometry.Pos;
import javafx.scene.Group;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.scene.paint.Paint;
import javafx.scene.text.Font;
import javafx.stage.Stage;
import weka.attributeSelection.GainRatioAttributeEval;
import weka.attributeSelection.Ranker;
import weka.classifiers.Classifier;
import weka.classifiers.bayes.NaiveBayes;
import weka.classifiers.evaluation.Evaluation;
import weka.classifiers.meta.AdaBoostM1;
import weka.classifiers.meta.Bagging;
import weka.classifiers.meta.FilteredClassifier;
import weka.classifiers.meta.RandomSubSpace;
import weka.classifiers.meta.Vote;
import weka.classifiers.misc.SerializedClassifier;
import weka.classifiers.rules.PART;
import weka.classifiers.trees.J48;
import weka.classifiers.trees.RandomForest;
import weka.core.Attribute;
import weka.core.DenseInstance;
import weka.core.Instance;
import weka.core.Instances;
import weka.core.converters.ArffSaver;
import weka.core.converters.ConverterUtils.DataSink;
import weka.core.converters.ConverterUtils.DataSource;
import weka.filters.Filter;
import weka.filters.supervised.attribute.AttributeSelection;
import weka.filters.unsupervised.attribute.AddValues;
import weka.filters.unsupervised.attribute.NumericToNominal;
import weka.filters.unsupervised.instance.RemoveRange;

public class PhishingWebsiteDetector extends Application{

	private TextField urlTf = new TextField();
	private Label predictedResult = new Label();
	private Button startClassification = new Button("PREDICT");
	
	private Classifier myPredictor = new MyClassifier();
	private String dataSourcePath = "./phishing_data_no_similar.arff";
	private Instances trainingData, test;
	
	@Override
	public void start(Stage stage) {

		stage.setScene(buildGUI());
		stage.setTitle("Phishy Website Detector");
		stage.show();
		
		DataSource source = null;
		try {
			
			source = new DataSource(dataSourcePath);
			trainingData = source.getDataSet(); 
			trainingData.setClassIndex(trainingData.numAttributes()-1);
			
			myPredictor.buildClassifier(trainingData);
			
			ArrayList<Attribute> testAl = new ArrayList<Attribute>();
			
			for(int i = 0; i<trainingData.numAttributes(); ++i) {
				String a = trainingData.attribute(i).name();
				testAl.add(new Attribute(a));
			}
			
			test = new Instances("Test", testAl,1);
			test.setClassIndex(test.numAttributes()-1);
			
		} catch (Exception e1) {
			System.out.println("There was a problem in data source path");
		}
		

		
		startClassification.setOnAction((ActionEvent ev) -> {
			
			predictedResult.setText("");
			String url = urlTf.getText();
			String host = null;
			try {
				 host = new URI(url).getHost();
				
			} catch (URISyntaxException e1) {
				System.out.println("Malformed URL");
			}
			
			if(host != null) {
					
				
				double[] features = FeaturesExtractor.extract(url, test.numAttributes());
				Instance unlabeledInstance = new DenseInstance(1.0,features);
				test.add(unlabeledInstance);
				NumericToNominal ntn = new NumericToNominal();
				String[] opt = new String[2];
				opt[0] = "-R";
				opt[1] = "first-last";
				Instances newTest = null;
				try{
					ntn.setOptions(opt);
					ntn.setInputFormat(test);
					newTest = Filter.useFilter(test, ntn);
				}catch(Exception e) {
					System.out.println("There was a problem in applying NumeriToNominal Filter");
				
				}
				Instances newTest2 = new Instances(newTest);
				
				for(int i=0; i<trainingData.numAttributes(); ++i) {
					
					Enumeration<Object> distinctValues = trainingData.attribute(i).enumerateValues();
					ArrayList<String> values = new ArrayList<String>();
					while(distinctValues.hasMoreElements())
						values.add(distinctValues.nextElement().toString());
					
						AddValues av = new AddValues();
						av.setSort(true);
						av.setAttributeIndex(String.valueOf(i+1));
						String commaValues = "";
						for(String label: values)
							commaValues +=label + ",";
						av.setLabels(commaValues);
						
						try {
							av.setInputFormat(newTest2);
							newTest2 = Filter.useFilter(newTest2, av);
						} catch (Exception e) {
							System.out.println("There was a problem");
						}
	
	
				
				}	
					
				try {
					//DataSink.write("./prova.arff", newTest2);
					//System.out.println(newTest2.lastInstance());
					double[] predictedDistribution = myPredictor.distributionForInstance(newTest2.lastInstance());
					double predictedClass =  myPredictor.classifyInstance(newTest2.lastInstance());
					setResultLabel(predictedDistribution, predictedClass);
					
					System.out.println("Class Prediction : " + predictedClass);
					System.out.println("Result: " + predictedDistribution[0] + "\t" + predictedDistribution[1]);

	
				}catch(Exception e) {
					//http://elon-promo.com/bitcoin/
					//http://www.tesla-gifting.site
					//e.printStackTrace();
						System.out.println("Unable to predict");
				}
				
			}else {
				System.out.println("Malformed URI");
			}
			
		});
		/*
		DataSource source1 = null;
		try {
			 source1 = new DataSource(dataSourcePath);
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		Instances data = source.getDataSet();
		data.setClassIndex(data.numAttributes()-1);
		ArrayList<Attribute> al = new ArrayList<>();
		al.add(new Attribute("Key_Scheme"));
		al.add(new Attribute("Key_Run"));
		al.add(new Attribute("ROC"));
		al.add(new Attribute("Precision"));
		
		Instances outInst = new Instances("vote", al,10);
		
		Vote v = new Vote();
		Bagging bg = new Bagging();
		PART pa = new PART();
		RandomSubSpace rss = new RandomSubSpace();
		
		rss.setClassifier(pa);
		bg.setClassifier(rss);
		
		Bagging bg1 = new Bagging();
		RandomForest rf = new RandomForest();
		RandomSubSpace rss1 = new RandomSubSpace();
		
		rss1.setClassifier(rf);
		bg1.setClassifier(rss1);
		
		Classifier[] c = new Classifier[2];
		c[0] = bg;
		c[1] = bg1;
		v.setClassifiers(c);
		
		for(int i = 1; i<=10; ++i) {
			
			Evaluation eval = new Evaluation(data);
			eval.crossValidateModel(v, data, 5, new Random(i));

			
			double[] values = new double[outInst.numAttributes()];
			values[0] = 0;
			values[1] = i;
			values[2] = eval.areaUnderROC(data.classAttribute().indexOfValue("-1"));
			values[3] = eval.pctCorrect();
			
			Instance inst = new DenseInstance(1.0,values);
			outInst.add(inst);
			System.out.println("Results " + i + "\n");
			
		}
		
		//System.out.println(outInst);
		ArffSaver saver = new ArffSaver();
		saver.setFile(new File("./vote.arff"));
		saver.setInstances(outInst);
		saver.writeBatch();
		*/
	}
	
	
	public Scene buildGUI() {
		
		urlTf.setMinWidth(300);
		//urlTf.setText("https://www.google.com");
		HBox urlBox = new HBox(5,new Label("Insert URL:"), urlTf);
		HBox buttonBox = new HBox(5, startClassification);
		buttonBox.setAlignment(Pos.CENTER);
		urlBox.setAlignment(Pos.CENTER);
		HBox resultBox = new HBox(new Label("Predicted Result: "), predictedResult);
		VBox vbox = new VBox(40, urlBox,buttonBox, resultBox);
		Group root = new Group(vbox);
		Scene scene = new Scene(root, 400,300);
		
		return scene;
		
	}
	
	public void setResultLabel(double[] predictedDistribution, double predictedClass) {
		
		if(predictedClass == 0) {
			
			predictedResult.setText("PHISHY " + Math.round(predictedDistribution[0]*100) + "%"  );
			predictedResult.setTextFill(Color.RED);
			predictedResult.setStyle("-fx-font-weight: bold;");
			
			
		}else if(predictedClass == 1) {
			
			predictedResult.setText("LEGITIMATE " + Math.round(predictedDistribution[1]*100) + "%"  ); 
			predictedResult.setTextFill(Color.GREEN);
			predictedResult.setStyle("-fx-font-weight: bold;");
			
		}else{
			
			predictedResult.setText( 
					"Phishing " + Math.round(predictedDistribution[0]*100) + "%" + "\n" + "Legitimate " +
					Math.round(predictedDistribution[1]*100) + "%"  ); 
			
			
		}
		
	}
	
	
	private void eliminateIdentityInstances() {
		try {
			DataSource dataset = new DataSource("./phishing_data_reduced.arff");
			Instances inst = dataset.getDataSet();
			inst.setClassIndex(inst.numAttributes()-1);
			
			ArrayList<Attribute> ar = new ArrayList<Attribute>();
			
			//int numInst = inst.numInstances();
			ArrayList<Integer> toEliminate = new ArrayList<Integer>();
			String toPrint = "";
			for(int i = 0;  i<inst.numInstances();++i) {
				
				Instance reference = inst.get(i);
				
				for(int k = 0; k<inst.numInstances(); ++k) {
					
					if(k==i || toEliminate.contains(k) || (inst.get(k).stringValue(30).equals(reference.stringValue(30))) )
						continue;
					
					Instance temp = inst.get(k);
					
					int numEq = 0;
					
					for(int j = 0; j<inst.numAttributes()-1; ++j) {
						
						if(temp.stringValue(j).equals(reference.stringValue(j)))
							numEq++;
						
						
					}
					
					if(numEq/(reference.numAttributes()-1) >= 0.85) {
						//inst.delete(k);
						toEliminate.add(k);
						//System.out.println("Inserito " + k + " uguale a " + i);
					}
					
				}
				
			}
			
			System.out.println(toEliminate.size());
			String indexes = "";
			for(int i = 0; i<toEliminate.size(); ++i)
				indexes += toEliminate.get(i) + ",";
			
			indexes = indexes.substring(0,indexes.length()-1);
			
			RemoveRange rg = new RemoveRange();
			rg.setInstancesIndices(indexes);
			
			rg.setInputFormat(inst);
			inst = Filter.useFilter(inst, rg);
			
			DataSink.write("./phishing_data_no_similar_class.arff", inst);
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
