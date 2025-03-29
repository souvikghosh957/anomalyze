package com.threat.anomalyze.commons.util;

import org.apache.commons.math3.stat.Frequency;

import java.util.Iterator;
import java.util.Map;

/**
 * Utility class containing methods to calculate Shannon entropy.
 */
public class EntropyUtils {
    /**
     * Calculates the Shannon entropy of a given frequency distribution.
     *
     * @param freq the frequency distribution containing counts of elements
     * @return the Shannon entropy in bits, returns 0.0 if the distribution is empty
     */
    public static double calculateEntropy(Frequency freq) {
        long totalCount = freq.getSumFreq();
        if (totalCount <= 1) {
            return 0.0;
        }
        double entropy = 0.0;
        double log2Denominator = Math.log(2);
        Iterator<Map.Entry<Comparable<?>, Long>> iterator = freq.entrySetIterator();
        while (iterator.hasNext()) {
            Map.Entry<Comparable<?>, Long> entry = iterator.next();
            long count = entry.getValue();
            if (count > 0) {
                double probability = (double) count / totalCount;
                entropy -= probability * (Math.log(probability) / log2Denominator);
            }
        }
        return entropy;
    }
}