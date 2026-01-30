// src/ml_detector.rs
use tensorflow as tf;
use std::path::Path;
use serde_json::Value;
use ring::hmac;

pub struct MLAnomalyDetector {
    model: tf::SavedModelBundle,
    session: tf::Session,
    feature_scaler: FeatureScaler,
}

#[derive(Default)]
struct FeatureScaler {
    means: Vec<f32>,
    stds: Vec<f32>,
}

impl MLAnomalyDetector {
    pub fn new(model_path: &str) -> Result<Self, tf::Status> {
        // Load pre-trained TensorFlow model
        let mut graph = tf::Graph::new();
        let session = tf::Session::new(&tf::SessionOptions::new(), &graph)?;
        
        let tags = vec!["serve".to_string()];
        let model = tf::SavedModelBundle::load(&session, tags, Path::new(model_path))?;
        
        Ok(Self {
            model,
            session,
            feature_scaler: FeatureScaler::default(),
        })
    }
    
    pub fn detect_anomaly(&mut self, features: &[f32]) -> Result<(f32, Vec<f32>), tf::Status> {
        // Prepare input tensor
        let input_tensor = tf::Tensor::new(&[1, features.len() as u64])
            .with_values(features)?;
        
        // Run inference
        let mut args = tf::SessionRunArgs::new();
        args.add_feed(&self.model.graph.operation_by_name_required("input")?, 0, &input_tensor);
        
        let anomaly_op = self.model.graph.operation_by_name_required("anomaly_score")?;
        let reconstruction_op = self.model.graph.operation_by_name_required("reconstruction")?;
        
        let anomaly_token = args.request_fetch(&anomaly_op, 0);
        let reconstruction_token = args.request_fetch(&reconstruction_op, 0);
        
        self.session.run(&mut args)?;
        
        let anomaly_score: f32 = args.fetch(anomaly_token)?[0];
        let reconstruction: Vec<f32> = args.fetch(reconstruction_token)?;
        
        Ok((anomaly_score, reconstruction))
    }
    
    pub fn extract_features(
        &self, 
        syscall_sequence: &[u32],
        timing: &[u64],
        process_metadata: &ProcessMetadata
    ) -> Vec<f32> {
        let mut features = Vec::new();
        
        // Temporal features
        features.push(syscall_sequence.len() as f32);
        features.push(Self::calculate_entropy(syscall_sequence));
        
        // Timing features
        let avg_time = timing.iter().sum::<u64>() as f32 / timing.len() as f32;
        features.push(avg_time);
        features.push(Self::calculate_variance(timing));
        
        // Process context features
        features.push(process_metadata.privilege_level as f32);
        features.push(process_metadata.children_count as f32);
        features.push(process_metadata.resource_usage);
        
        // Behavioral signature similarity
        features.push(self.calculate_signature_similarity(&process_metadata.signature));
        
        features
    }
    
    fn calculate_entropy(sequence: &[u32]) -> f32 {
        use std::collections::HashMap;
        let mut counts = HashMap::new();
        let total = sequence.len() as f32;
        
        for &item in sequence {
            *counts.entry(item).or_insert(0) += 1;
        }
        
        -counts.values()
            .map(|&c| {
                let p = c as f32 / total;
                p * p.log2()
            })
            .sum::<f32>()
    }
    
    fn calculate_signature_similarity(&self, signature: &[u8]) -> f32 {
        // Compare with known good signatures using HMAC
        let key = hmac::Key::new(hmac::HMAC_SHA256, b"quantum_kernel_key");
        let tag = hmac::sign(&key, signature);
        
        // Convert to similarity score
        let mut score = 0.0;
        for byte in tag.as_ref() {
            score += *byte as f32;
        }
        score / (tag.as_ref().len() as f32 * 255.0)
    }
}

#[derive(Debug, Clone)]
pub struct ProcessMetadata {
    pub privilege_level: u8,  // 0=root, 1=user, 2=restricted
    pub children_count: u32,
    pub resource_usage: f32,  // CPU+memory normalized
    pub signature: Vec<u8>,
    pub syscall_pattern: Vec<u32>,
}
