
import java.io.File;
import java.net.URI;

import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Enumeration;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.event.ActionEvent;
import javafx.geometry.Pos;
import javafx.scene.Group;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.stage.Stage;
import weka.classifiers.Classifier;
import weka.core.Attribute;
import weka.core.DenseInstance;
import weka.core.Instance;
import weka.core.Instances;
import weka.core.converters.ConverterUtils.DataSink;
import weka.core.converters.ConverterUtils.DataSource;
import weka.filters.Filter;
import weka.filters.unsupervised.attribute.AddValues;
import weka.filters.unsupervised.attribute.NumericToNominal;
import weka.filters.unsupervised.instance.RemoveRange;


public class PhishingWebsiteDetector extends Application{

	private TextField urlTf = new TextField();
	private Label predictedResult = new Label();
	private Button startClassification = new Button("PREDICT");
	private ImageView loading = new ImageView();
	
	private Classifier myPredictor = new MyClassifier();
	private String dataSourcePath = "./phishing_data_no_similar.arff";
	private Instances trainingData, test;
	
	private String loadingSourcePath = "img/loading.gif";
	
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
				
				loading.setImage(new Image(new File(loadingSourcePath).toURI().toString()));
				Thread t = new Thread(new BackgroundExtractor(url));
				t.start();
				
			}else {
				System.out.println("Malformed URI");
			}
			
		});
		
	}
	
	
	public Scene buildGUI() {
		
		urlTf.setMinWidth(300);
		urlTf.setPromptText("e.g. https://www.google.com");
		urlTf.setFocusTraversable(false);
		loading.setFitHeight(30);
		loading.setFitWidth(30);
		loading.setPreserveRatio(true);
		loading.setImage(null);
		HBox urlBox = new HBox(10,new HBox(),new Label("URL:"), urlTf);
		HBox foo = new HBox();
		foo.setPrefWidth(60);
		HBox buttonBox = new HBox(20, foo, startClassification, loading);
		buttonBox.setAlignment(Pos.CENTER);
		urlBox.setAlignment(Pos.CENTER);
		HBox resultBox = new HBox(10, new HBox(),new Label("Predicted Result: "), predictedResult);
		VBox transparent = new VBox(10,new VBox(),urlBox);
		VBox vbox = new VBox(40, transparent, buttonBox, resultBox);
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
	
	private class BackgroundExtractor implements Runnable{
		
		private String url = "";
		
		public BackgroundExtractor(String u) {
			// TODO Auto-generated constructor stub
			url = u;
		}	
		@Override
		public void run() {
			// TODO Auto-generated method stub
			
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
				loading.setImage(null);
			
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
						loading.setImage(null);
					}


			
			}	
				
			try {
				double[] predictedDistribution = myPredictor.distributionForInstance(newTest2.lastInstance());
				double predictedClass =  myPredictor.classifyInstance(newTest2.lastInstance());
				
				Platform.runLater(()->{
					setResultLabel(predictedDistribution, predictedClass);
				});
				
				System.out.println("Class Prediction : " + predictedClass);
				System.out.println("Result: " + predictedDistribution[0] + "\t" + predictedDistribution[1]);


			}catch(Exception e) {
					System.out.println("Unable to predict");
			}finally {
				loading.setImage(null);
			}
		}
		
	}
}
