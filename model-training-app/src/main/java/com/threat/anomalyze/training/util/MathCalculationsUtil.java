package com.threat.anomalyze.training.util;

import smile.data.DataFrame;

import java.util.HashMap;
import java.util.Map;

public class MathCalculationsUtil {

    /**
     * Computes the mean of each feature for normal instances (scores < threshold) in the training data.
     *
     * @param df        The DataFrame containing the feature data.
     * @param scores    The anomaly scores for each instance.
     * @param threshold The threshold to determine normal instances.
     * @return A map of feature names to their mean values for normal instances.
     */
    public static Map<String, Double> computeFeatureMeans(DataFrame df, double[] scores, double threshold) {
        Map<String, Double> means = new HashMap<>();
        String[] names = df.names();
        for (String name : names) {
            if (!name.equals("ip") && !name.equals("timestamp")) {
                double sum = 0.0;
                int count = 0;
                for (int i = 0; i < df.size(); i++) {
                    if (scores[i] < threshold) { // Select normal instances
                        sum += df.getDouble(i, df.schema().indexOf(name));
                        count++;
                    }
                }
                means.put(name, count > 0 ? sum / count : 0.0);
            }
        }
        return means;
    }

    /**
     * Computes the standard deviation of each feature for normal instances in the training data.
     *
     * @param df        The DataFrame containing the feature data.
     * @param scores    The anomaly scores for each instance.
     * @param means     The map of feature means.
     * @param threshold The threshold to determine normal instances.
     * @return A map of feature names to their standard deviation values for normal instances.
     */
    public static Map<String, Double> computeFeatureStds(DataFrame df, double[] scores, Map<String, Double> means, double threshold) {
        Map<String, Double> stds = new HashMap<>();
        String[] names = df.names();
        for (String name : names) {
            if (!name.equals("ip") && !name.equals("timestamp")) {
                double sumSq = 0.0;
                int count = 0;
                for (int i = 0; i < df.size(); i++) {
                    if (scores[i] < threshold) {
                        double val = df.getDouble(i, df.schema().indexOf(name));
                        sumSq += Math.pow(val - means.get(name), 2);
                        count++;
                    }
                }
                double variance = count > 0 ? sumSq / count : 0.0;
                stds.put(name, Math.max(Math.sqrt(variance), 1e-10)); // Prevent zero std
            }
        }
        return stds;
    }
}