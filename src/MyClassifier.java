import java.io.File;
import weka.attributeSelection.GainRatioAttributeEval;
import weka.attributeSelection.Ranker;
import weka.classifiers.AbstractClassifier;
import weka.classifiers.meta.Bagging;
import weka.classifiers.meta.FilteredClassifier;
import weka.classifiers.meta.RandomSubSpace;
import weka.classifiers.misc.SerializedClassifier;
import weka.classifiers.rules.PART;
import weka.core.Capabilities;
import weka.core.Debug;
import weka.core.Instance;
import weka.core.Instances;
import weka.filters.supervised.attribute.AttributeSelection;


public class MyClassifier extends AbstractClassifier{

	private static final long serialVersionUID = 1L;
	SerializedClassifier sc;
	private String classifierModelPath = "./myClassifier";
	
	@Override
	public void buildClassifier(Instances data) throws Exception {
		// TODO Auto-generated method stub
		
		//saveModel(data);
		
		System.out.println("-------  START LOADING MODEL  --------");
		
		sc = new SerializedClassifier();
		sc.setModelFile(new File(classifierModelPath));
	
		System.out.println("-------  END  --------");
	}
	
	private void saveModel(Instances data) throws Exception {

		PART pa = new PART();
		Bagging bg = new Bagging();
		RandomSubSpace rss = new RandomSubSpace();
		FilteredClassifier fc = new FilteredClassifier();
		
		AttributeSelection as = new AttributeSelection();
		as.setEvaluator(new GainRatioAttributeEval());
		as.setSearch(new Ranker());
		fc.setFilter(as);
		fc.setClassifier(pa);
		
		rss.setClassifier(fc);
		bg.setClassifier(rss);
		bg.setPrintClassifiers(true);
		//rf.setPrintClassifiers(true);
		System.out.println("-------  START TRAINING  --------");
		
		bg.buildClassifier(data);
		
		System.out.println("-------  END  --------");
		
		Debug.saveToFile("./myClassifier", bg);
		
	}
	@Override
	public double classifyInstance(Instance instance) throws Exception {
		// TODO Auto-generated method stub
		return sc.classifyInstance(instance);
	}

	@Override
	public double[] distributionForInstance(Instance instance) throws Exception {
		// TODO Auto-generated method stub
		return sc.distributionForInstance(instance);
	}

	@Override
	public Capabilities getCapabilities() {
		// TODO Auto-generated method stub
		return null;
	}

}
