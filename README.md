# IntrusionDetectionSystemWork

This project explores a potential avenue of application for machine learning algorithms in intrusion detection for cyber security. In each of the first two parts there are comprehensive reports with more specific information and the third part is a summary and analysis of the first two.

[Part 1 Report](https://github.com/phogya/IntrusionDetectionSystemWork/blob/master/Part1_DecisionTrees/docs/ISSreport.pdf)

[Part 2 Report](https://github.com/phogya/IntrusionDetectionSystemWork/blob/master/Part2_NeuralNetworks/docs/ISSreport.pdf)

[Part 3 Analysis](https://github.com/phogya/IntrusionDetectionSystemWork/blob/master/Part3_Analysis/Analysis.pdf)

## Overview

Traffic was classified using Decision Trees in Part 1 and Neural Networks in Part 2. Labeled pcap files, packet captures, were used to train the algorithms and find patterns to differentiate between malicious and normal traffic. We were only concerned with detecting attacks using this information and did not look into detecting other attack avenues. Both algorithms were trained with two different approaches each. As an anomaly-basd IDS, which attempts to classify attacks by detecting deviations from normal behaviour. And as a signature-based IDS, which classifies specific attacks using some pattern. The Decision Trees proved very effective at classifying attacks using both approaches but the Neural Networks were significantly less effective. I will explain potential reasons for this below. 
  
Classifying network attacks is a particularly complex problem to solve with ML algorithms. Firstly there are a limited number of useful and effective features. Rule syntaxes for IDS software like Snort and Suricata are limited in what can be used, only IP addresses and Port numbers support range comparisons. Second, many potential features can be spoofed in one way or another, especially IP addresses. Third, the range of IPv4 addresses is over 4 billion. A Neural Network would need to run for many epochs to find the small ranges of addresses associated with attacks whereas Decision Trees have no problem identifying miniscule ranges where attacks are more likely. Unfortunately I did not have access to such computational resources while doing this project. Altogether the resources and tools available make this a difficult problem for Neural Networks to classify effectively. However Suricata now supports Lua scripting to support more features and it's certainly possible to write a new IDS tool with a more flexible approach to rule syntax. Using a more flexible rule syntax and re-examining the data to determine more reliable key features may yield better results. Additionally using the appropriate computational resources to match the complexity of Neural Networks would surely improve results as well.
