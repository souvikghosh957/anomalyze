package com.threat.anomalyze.training.util;

import lombok.extern.slf4j.Slf4j;
import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartUtils;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.chart.plot.XYPlot;
import org.jfree.chart.renderer.xy.XYLineAndShapeRenderer;
import org.jfree.data.xy.XYSeries;
import org.jfree.data.xy.XYSeriesCollection;
import smile.data.DataFrame;

import java.io.File;
import java.io.IOException;

@Slf4j
public class ScatterPlotUtils {

    public static void saveScatterPlot(DataFrame data, String filePath) throws IOException {
        XYSeries series = new XYSeries("Data Points");

        double[][] dataArray = data.toArray();
        for (double[] point : dataArray) {
            series.add(point[0], point[1]); // Assuming 2D data, modify as needed
        }

        XYSeriesCollection dataset = new XYSeriesCollection(series);
        JFreeChart scatterPlot = ChartFactory.createScatterPlot(
                "Scatter Plot of Trained Data",
                "X-Axis",
                "Y-Axis",
                dataset,
                PlotOrientation.VERTICAL,
                true,
                true,
                false
        );

        XYPlot plot = (XYPlot) scatterPlot.getPlot();
        XYLineAndShapeRenderer renderer = new XYLineAndShapeRenderer();
        renderer.setSeriesShapesVisible(0, true);
        renderer.setSeriesLinesVisible(0, false);
        plot.setRenderer(renderer);

        // Save the scatter plot as an image
        File imageFile = new File(filePath);
        ChartUtils.saveChartAsPNG(imageFile, scatterPlot, 800, 600);
        log.info("Scatter plot saved to {}", filePath);
    }
}