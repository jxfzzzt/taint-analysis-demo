package analysis;

import reporting.Reporter;
import soot.*;

import java.util.Map;

/**
 * Runner class for starting the dataflow analysis
 */
public class MainClass {


    public static void main(String[] args) {
        // source node
        // sink node
        // taint var
        runAnalysis(new Reporter());
    }

    public static void runAnalysis(final Reporter reporter) {
        G.reset();

        // Register the transform
        Transform transform = new Transform("jtp.analysis", new BodyTransformer() {
            @Override
            protected void internalTransform(Body b, String phaseName, Map<String, String> options) {
                // Create the analysis
                // Intra 方法内的分析 (关注)
                // Inter 方法间的分析
                IntraproceduralAnalysis ipa = new IntraproceduralAnalysis(b, reporter);
                ipa.doAnalysis();
            }

        });
        PackManager.v().getPack("jtp").add(transform);

        // Run Soot
        Main.main(
                new String[]{"-pp", "-process-dir", "./targetsBin", "-src-prec", "class", "-output-format", "none"});
    }

}
