from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, List
import time
import google.generativeai as genai
import re
import base64
from io import BytesIO
from PIL import Image
from PIL.ExifTags import TAGS
import hashlib
import requests
import numpy as np
from scipy.signal import convolve2d
from scipy import ndimage
import piexif
from dataclasses import dataclass, asdict
from datetime import datetime
import os

app = FastAPI(title="TrustNet AI - Forensic Media Verifier", version="3.0.0")


# CORS settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]
)

@dataclass
class ForensicFlag:
    """Individual forensic flag with severity"""
    category: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    description: str
    score_impact: int
    evidence: str

class DeepMetadataAnalyzer:
    """Advanced forensic metadata analyzer for AI detection"""
    
    def __init__(self):
        # AI software signatures (comprehensive list)
        self.AI_SOFTWARE_SIGNATURES = [
            "stable diffusion", "stablediffusion", "sd-webui", "automatic1111", "a1111",
            "midjourney", "dall-e", "dalle", "dall·e", "openai", "chatgpt",
            "dreamstudio", "comfyui", "invokeai", "deforum", "controlnet",
            "firefly", "adobe firefly", "craiyon", "nightcafe", "artbreeder",
            "runway", "gen-2", "sora", "synthesia", "d-id", "pictory",
            "leonardo.ai", "bluewillow", "playground", "lexica"
        ]
        
        # Common AI generation resolutions
        self.AI_RESOLUTIONS = {
            256, 384, 448, 512, 576, 640, 704, 768, 832, 896, 960, 1024,
            1152, 1216, 1280, 1344, 1408, 1472, 1536, 1600, 1664, 1728,
            1792, 1856, 1920, 1984, 2048
        }
        
        # Camera manufacturers (real photos should have these)
        self.REAL_CAMERA_MAKES = {
            "canon", "nikon", "sony", "fujifilm", "olympus", "panasonic",
            "leica", "pentax", "hasselblad", "phase one", "samsung",
            "apple", "google", "xiaomi", "huawei", "oneplus", "motorola"
        }
        
        # Laplacian kernel for texture analysis
        self.LAPLACIAN_KERNEL = np.array([[0, 1, 0], [1, -4, 1], [0, 1, 0]], dtype=np.float32)
        
        # Scoring weights
        self.WEIGHTS = {
            'exif_presence': 15,
            'camera_data': 20,
            'ai_software': 35,
            'resolution_pattern': 15,
            'texture_analysis': 10,
            'color_profile': 5,
            'compression': 5,
            'timestamp_consistency': 5,
            'gps_data': 3,
            'lens_data': 5,
            'edit_history': 10,
            'file_format': 3
        }
        
        # AI text patterns (for text analysis)
        self.AI_TEXT_PATTERNS = [
            'delve', 'leverage', 'comprehensive', 'robust', 'paradigm',
            'utilize', 'facilitate', 'moreover', 'furthermore', 'nonetheless',
            'it is important to note', 'in conclusion', 'to summarize',
            'as an ai', 'i apologize', 'i don\'t have personal', 
            'my knowledge cutoff', 'as of my last update'
        ]
        
        # Video AI signatures
        self.VIDEO_AI_SIGNATURES = [
            b'sora', b'runway', b'gen-2', b'synthesia', b'd-id',
            b'pictory', b'descript', b'heygen', b'colossyan'
        ]
    
    def analyze_image(self, image_data: bytes) -> Dict:
        """Comprehensive forensic analysis of image"""
        flags = []
        total_score = 0
        
        try:
            image = Image.open(BytesIO(image_data))
            
            # 1. EXIF Data Extraction
            exif_flags, exif_score, exif_data = self._analyze_exif(image_data)
            flags.extend(exif_flags)
            total_score += exif_score
            
            # 2. Resolution and Dimension Analysis
            res_flags, res_score = self._analyze_resolution(image)
            flags.extend(res_flags)
            total_score += res_score
            
            # 3. Texture and Frequency Analysis
            texture_flags, texture_score, texture_data = self._analyze_texture(image)
            flags.extend(texture_flags)
            total_score += texture_score
            
            # 4. Color Profile Analysis
            color_flags, color_score = self._analyze_color_profile(image)
            flags.extend(color_flags)
            total_score += color_score
            
            # 5. Compression Analysis
            comp_flags, comp_score = self._analyze_compression(image, image_data)
            flags.extend(comp_flags)
            total_score += comp_score
            
            # 6. Edge Detection Analysis
            edge_flags, edge_score = self._analyze_edges(image)
            flags.extend(edge_flags)
            total_score += edge_score
            
            # 7. Noise Pattern Analysis
            noise_flags, noise_score = self._analyze_noise(image)
            flags.extend(noise_flags)
            total_score += noise_score
            
            # Generate verdict
            verdict, risk_level = self._generate_verdict(total_score, flags)
            
            return {
                'risk_score': min(100, total_score),
                'verdict': verdict,
                'risk_level': risk_level,
                'flags': [asdict(f) for f in flags],
                'flag_count': len(flags),
                'critical_flags': len([f for f in flags if f.severity == 'CRITICAL']),
                'high_flags': len([f for f in flags if f.severity == 'HIGH']),
                'exif_data': exif_data,
                'texture_analysis': texture_data,
                'analysis_timestamp': datetime.now().isoformat(),
                'file_hash': hashlib.sha256(image_data).hexdigest(),
                'file_size': len(image_data),
                'dimensions': f"{image.size[0]}x{image.size[1]}",
                'format': image.format
            }
            
        except Exception as e:
            print(f"Analysis error: {e}")
            return {
                'risk_score': 50,
                'verdict': 'Analysis failed',
                'risk_level': 'UNKNOWN',
                'error': str(e)
            }
    
    def _analyze_exif(self, image_data: bytes) -> tuple:
        """Deep EXIF metadata analysis"""
        flags = []
        score = 0
        exif_dict = {}
        
        try:
            exif = piexif.load(image_data)
            
            # Extract all EXIF data
            for ifd_name, ifd_data in exif.items():
                if ifd_name == "thumbnail":
                    continue
                for tag_id, value in ifd_data.items():
                    tag_name = piexif.TAGS.get(ifd_name, {}).get(tag_id, {}).get("name", str(tag_id))
                    if isinstance(value, bytes):
                        value = value.decode('utf-8', errors='ignore')
                    exif_dict[f"{ifd_name}.{tag_name}"] = str(value)
            
            # Check 1: No EXIF at all (CRITICAL)
            if not exif_dict or len(exif_dict) < 3:
                flags.append(ForensicFlag(
                    category="EXIF",
                    severity="CRITICAL",
                    description="No EXIF metadata found",
                    score_impact=self.WEIGHTS['exif_presence'],
                    evidence="AI-generated images typically lack camera EXIF data"
                ))
                score += self.WEIGHTS['exif_presence']
            
            # Check 2: Camera make/model
            camera_fields = ['0th.Make', '0th.Model']
            camera_data = {k: v for k, v in exif_dict.items() if any(cf in k for cf in camera_fields)}
            if not camera_data:
                flags.append(ForensicFlag(
                    category="EXIF",
                    severity="HIGH",
                    description="No camera make or model found",
                    score_impact=self.WEIGHTS['camera_data'],
                    evidence="Authentic photos should contain camera information"
                ))
                score += self.WEIGHTS['camera_data']
            else:
                camera_make = next(iter(camera_data.values()), '').lower()
                if not any(m in camera_make for m in self.REAL_CAMERA_MAKES):
                    flags.append(ForensicFlag(
                        category="EXIF",
                        severity="MEDIUM",
                        description=f"Unknown camera manufacturer: {camera_make}",
                        score_impact=10,
                        evidence="Camera make not in known manufacturers list"
                    ))
                    score += 10
            
            # Check 3: AI software signatures (CRITICAL)
            software_fields = ['0th.Software', 'Exif.UserComment', '0th.ImageDescription', '0th.Artist']
            for field in software_fields:
                value = exif_dict.get(field, '').lower()
                for signature in self.AI_SOFTWARE_SIGNATURES:
                    if signature in value:
                        flags.append(ForensicFlag(
                            category="EXIF",
                            severity="CRITICAL",
                            description=f"AI software signature detected: '{exif_dict.get(field)}'",
                            score_impact=self.WEIGHTS['ai_software'],
                            evidence=f"Found '{signature}' in {field}"
                        ))
                        score += self.WEIGHTS['ai_software']
                        break
            
            # Check 4: Timestamp consistency
            timestamp_fields = ['0th.DateTime', 'Exif.DateTimeOriginal', 'Exif.DateTimeDigitized']
            timestamps = [exif_dict.get(f) for f in timestamp_fields if exif_dict.get(f)]
            
            if not timestamps:
                flags.append(ForensicFlag(
                    category="EXIF",
                    severity="MEDIUM",
                    description="No timestamp data found",
                    score_impact=self.WEIGHTS['timestamp_consistency'],
                    evidence="Real photos contain original capture timestamps"
                ))
                score += self.WEIGHTS['timestamp_consistency']
            elif len(set(timestamps)) > 1:
                flags.append(ForensicFlag(
                    category="EXIF",
                    severity="LOW",
                    description="Inconsistent timestamps detected",
                    score_impact=3,
                    evidence="Multiple different timestamp values found"
                ))
                score += 3
            
            # Check 5: GPS data
            has_gps = any(k.startswith("GPS") for k in exif_dict.keys())
            if not has_gps:
                flags.append(ForensicFlag(
                    category="EXIF",
                    severity="LOW",
                    description="No GPS coordinates",
                    score_impact=self.WEIGHTS['gps_data'],
                    evidence="Many real photos contain location data"
                ))
                score += self.WEIGHTS['gps_data']
            
            # Check 6: Lens data
            lens_fields = ['Exif.LensModel', 'Exif.FocalLength', 'Exif.FNumber']
            lens_data = {k: v for k, v in exif_dict.items() if any(lf in k for lf in lens_fields)}
            if not lens_data and camera_data:
                flags.append(ForensicFlag(
                    category="EXIF",
                    severity="MEDIUM",
                    description="Missing lens information",
                    score_impact=self.WEIGHTS['lens_data'],
                    evidence="Camera present but no lens data (suspicious)"
                ))
                score += self.WEIGHTS['lens_data']
            
        except Exception as e:
            flags.append(ForensicFlag(
                category="EXIF",
                severity="HIGH",
                description="Failed to read EXIF data",
                score_impact=self.WEIGHTS['exif_presence'],
                evidence=f"Error: {str(e)}"
            ))
            score += self.WEIGHTS['exif_presence']
        
        return flags, score, exif_dict
    
    def _analyze_resolution(self, image: Image.Image) -> tuple:
        """Analyze resolution patterns"""
        flags = []
        score = 0
        
        width, height = image.size
        
        # Check 1: Perfect square with AI resolution
        if width == height and width in self.AI_RESOLUTIONS:
            flags.append(ForensicFlag(
                category="RESOLUTION",
                severity="CRITICAL",
                description=f"Perfect square AI resolution: {width}x{height}",
                score_impact=self.WEIGHTS['resolution_pattern'],
                evidence="Stable Diffusion/Midjourney common output size"
            ))
            score += self.WEIGHTS['resolution_pattern']
        
        # Check 2: Multiples of 64 (diffusion model requirement)
        elif width % 64 == 0 and height % 64 == 0:
            flags.append(ForensicFlag(
                category="RESOLUTION",
                severity="HIGH",
                description=f"Dimensions divisible by 64: {width}x{height}",
                score_impact=10,
                evidence="Latent diffusion models require 64-pixel multiples"
            ))
            score += 10
        
        # Check 3: Both dimensions in AI resolution set
        elif width in self.AI_RESOLUTIONS and height in self.AI_RESOLUTIONS:
            flags.append(ForensicFlag(
                category="RESOLUTION",
                severity="MEDIUM",
                description=f"Both dimensions match AI patterns: {width}x{height}",
                score_impact=8,
                evidence="Common AI generation resolutions"
            ))
            score += 8
        
        # Check 4: Unusual aspect ratio
        aspect_ratio = width / height
        common_ratios = [16/9, 4/3, 3/2, 1/1, 9/16, 3/4, 2/3]
        if not any(abs(aspect_ratio - r) < 0.05 for r in common_ratios):
            # Actually this might be real, so small penalty
            pass
        
        return flags, score
    
    def _analyze_texture(self, image: Image.Image) -> tuple:
        """Deep texture and frequency analysis"""
        flags = []
        score = 0
        texture_data = {}
        
        try:
            # Convert to grayscale
            gray = np.asarray(image.convert("L"), dtype=np.float32) / 255.0
            
            # 1. Laplacian variance (edge sharpness)
            laplacian = convolve2d(gray, self.LAPLACIAN_KERNEL, mode='same', boundary='symm')
            lap_variance = float(np.var(laplacian))
            texture_data['laplacian_variance'] = lap_variance
            
            if lap_variance < 0.0005:
                flags.append(ForensicFlag(
                    category="TEXTURE",
                    severity="CRITICAL",
                    description=f"Abnormally low texture variance: {lap_variance:.6f}",
                    score_impact=self.WEIGHTS['texture_analysis'],
                    evidence="AI images often have unnaturally smooth textures"
                ))
                score += self.WEIGHTS['texture_analysis']
            elif lap_variance < 0.002:
                flags.append(ForensicFlag(
                    category="TEXTURE",
                    severity="MEDIUM",
                    description=f"Low texture variance: {lap_variance:.6f}",
                    score_impact=5,
                    evidence="Smoother than typical camera photos"
                ))
                score += 5
            
            # 2. Gradient magnitude analysis
            gy, gx = np.gradient(gray)
            gradient_magnitude = np.sqrt(gx**2 + gy**2)
            grad_mean = float(np.mean(gradient_magnitude))
            texture_data['gradient_mean'] = grad_mean
            
            if grad_mean < 0.05:
                flags.append(ForensicFlag(
                    category="TEXTURE",
                    severity="MEDIUM",
                    description=f"Low gradient magnitude: {grad_mean:.6f}",
                    score_impact=4,
                    evidence="Lack of fine detail typical in AI generation"
                ))
                score += 4
            
            # 3. High-frequency content
            fft = np.fft.fft2(gray)
            fft_shift = np.fft.fftshift(fft)
            magnitude_spectrum = np.abs(fft_shift)
            
            # Analyze high frequencies
            h, w = magnitude_spectrum.shape
            center_h, center_w = h // 2, w // 2
            high_freq_region = magnitude_spectrum[:center_h//2, :center_w//2]
            high_freq_energy = float(np.sum(high_freq_region))
            texture_data['high_freq_energy'] = high_freq_energy
            
            if high_freq_energy < 1000:
                flags.append(ForensicFlag(
                    category="TEXTURE",
                    severity="LOW",
                    description=f"Low high-frequency energy: {high_freq_energy:.2f}",
                    score_impact=3,
                    evidence="AI images lack natural high-frequency detail"
                ))
                score += 3
            
        except Exception as e:
            texture_data['error'] = str(e)
        
        return flags, score, texture_data
    
    def _analyze_color_profile(self, image: Image.Image) -> tuple:
        """Analyze color profile and consistency"""
        flags = []
        score = 0
        
        # Check for ICC profile
        if 'icc_profile' not in image.info:
            flags.append(ForensicFlag(
                category="COLOR",
                severity="MEDIUM",
                description="Missing ICC color profile",
                score_impact=self.WEIGHTS['color_profile'],
                evidence="Camera photos typically embed color profiles"
            ))
            score += self.WEIGHTS['color_profile']
        
        # Check DPI
        dpi = image.info.get('dpi', (0, 0))
        if dpi in [(72, 72), (96, 96)]:
            flags.append(ForensicFlag(
                category="COLOR",
                severity="LOW",
                description=f"Screen-resolution DPI: {dpi}",
                score_impact=3,
                evidence="AI generators often use screen DPI instead of print DPI"
            ))
            score += 3
        
        return flags, score
    
    def _analyze_compression(self, image: Image.Image, image_data: bytes) -> tuple:
        """Analyze compression artifacts"""
        flags = []
        score = 0
        
        file_size = len(image_data)
        pixels = image.size[0] * image.size[1]
        bytes_per_pixel = file_size / pixels
        
        # PNG with no compression is suspicious
        if image.format == 'PNG' and bytes_per_pixel > 2:
            flags.append(ForensicFlag(
                category="COMPRESSION",
                severity="LOW",
                description=f"High bytes-per-pixel ratio: {bytes_per_pixel:.2f}",
                score_impact=2,
                evidence="Unusually large PNG file size"
            ))
            score += 2
        
        # Check for excessive quality
        if image.format == 'JPEG' and bytes_per_pixel > 1.5:
            flags.append(ForensicFlag(
                category="COMPRESSION",
                severity="LOW",
                description="High JPEG quality (minimal compression)",
                score_impact=self.WEIGHTS['compression'],
                evidence="AI generators often save at maximum quality"
            ))
            score += self.WEIGHTS['compression']
        
        return flags, score
    
    def _analyze_edges(self, image: Image.Image) -> tuple:
        """Analyze edge characteristics"""
        flags = []
        score = 0
        
        try:
            gray = np.asarray(image.convert("L"), dtype=np.float32)
            edges = ndimage.sobel(gray)
            edge_strength = float(np.std(edges))
            
            if edge_strength < 10:
                flags.append(ForensicFlag(
                    category="EDGES",
                    severity="MEDIUM",
                    description=f"Weak edge definition: {edge_strength:.2f}",
                    score_impact=4,
                    evidence="AI images often have soft, imprecise edges"
                ))
                score += 4
        except:
            pass
        
        return flags, score
    
    def _analyze_noise(self, image: Image.Image) -> tuple:
        """Analyze noise patterns"""
        flags = []
        score = 0
        
        try:
            # Convert to numpy array
            img_array = np.asarray(image.convert("RGB"), dtype=np.float32)
            
            # Calculate noise estimate
            noise_estimate = float(np.std(img_array - ndimage.gaussian_filter(img_array, sigma=1)))
            
            if noise_estimate < 2:
                flags.append(ForensicFlag(
                    category="NOISE",
                    severity="MEDIUM",
                    description=f"Abnormally low noise level: {noise_estimate:.2f}",
                    score_impact=5,
                    evidence="Real camera photos always have sensor noise"
                ))
                score += 5
        except:
            pass
        
        return flags, score
    
    def _generate_verdict(self, score: int, flags: List[ForensicFlag]) -> tuple:
        """Generate final verdict based on score and flags"""
        critical_count = len([f for f in flags if f.severity == 'CRITICAL'])
        
        if score >= 80 or critical_count >= 2:
            return "LIKELY AI-GENERATED", "CRITICAL"
        elif score >= 60 or critical_count >= 1:
            return "SUSPICIOUS - Possibly AI-generated", "HIGH"
        elif score >= 40:
            return "UNCERTAIN - Some AI indicators present", "MEDIUM"
        elif score >= 20:
            return "LIKELY AUTHENTIC - Minor anomalies", "LOW"
        else:
            return "APPEARS AUTHENTIC", "MINIMAL"

# Initialize analyzer
analyzer = DeepMetadataAnalyzer()

# Initialize Gemini for secondary validation
try:
    GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY")
    if not GOOGLE_API_KEY:
        raise ValueError("GOOGLE_API_KEY environment variable not set")
    genai.configure(api_key=GOOGLE_API_KEY)
    gemini_model = genai.GenerativeModel('gemini-pro')
    gemini_vision = genai.GenerativeModel('gemini-pro-vision')
    gemini_available = True
    print("✅ Gemini API available for secondary validation")
except (ValueError, Exception) as e:
    gemini_available = False
    print("⚠️ Running in metadata-only mode")

# Request models
class TextRequest(BaseModel):
    text: str

class ImageUrlRequest(BaseModel):
    url: str

class VideoRequest(BaseModel):
    video_url: Optional[str] = None
    video_description: Optional[str] = None

# API Routes
@app.get("/")
async def root():
    return {
        "service": "TrustNet AI - Forensic Media Verifier",
        "version": "3.0.0",
        "tagline": "Deep Metadata Analysis for AI Detection",
        "method": "Forensic metadata analysis with 12+ detection checks",
        "capabilities": ["Deep EXIF analysis", "Texture forensics", "Resolution patterns", "Color profiling"]
    }

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "analyzer": "active",
        "gemini_available": gemini_available,
        "timestamp": time.time()
    }

@app.post("/verify/image")
async def verify_image(file: UploadFile = File(...)):
    """Forensic image verification with deep metadata analysis"""
    if not file.content_type.startswith("image/"):
        raise HTTPException(400, "Invalid file type. Please upload an image.")
    
    try:
        image_data = await file.read()
        
        if len(image_data) > 10 * 1024 * 1024:
            raise HTTPException(400, "Image too large (max 10MB)")
        
        # PRIMARY: Forensic metadata analysis
        result = analyzer.analyze_image(image_data)
        
        # SECONDARY: Gemini visual validation (if available)
        if gemini_available:
            try:
                image = Image.open(BytesIO(image_data))
                prompt = f"""Based on this forensic analysis, does the image appear AI-generated?

Metadata Findings:
- Risk Score: {result['risk_score']}%
- Critical Flags: {result['critical_flags']}
- Verdict: {result['verdict']}

Provide brief confirmation: YES/NO and why."""
                
                response = gemini_vision.generate_content([prompt, image])
                result['gemini_validation'] = response.text
            except Exception as e:
                result['gemini_validation'] = f"Unavailable: {e}"
        
        return {
            "success": True,
            "verification": result,
            "filename": file.filename,
            "method": "forensic_metadata_analysis",
            "timestamp": time.time()
        }
    except Exception as e:
        raise HTTPException(500, f"Verification failed: {str(e)}")

@app.post("/verify/image-from-url")
async def verify_image_from_url(request: ImageUrlRequest):
    """Forensic verification from URL"""
    try:
        response = requests.get(request.url, stream=True, timeout=10)
        response.raise_for_status()
        
        content_type = response.headers.get('content-type')
        if not content_type or not content_type.startswith('image/'):
            raise HTTPException(400, f"URL does not point to a valid image")
        
        image_data = response.content
        
        if len(image_data) > 10 * 1024 * 1024:
            raise HTTPException(400, "Image too large (max 10MB)")
        
        result = analyzer.analyze_image(image_data)
        
        return {
            "success": True,
            "verification": result,
            "source_url": request.url,
            "method": "forensic_metadata_analysis",
            "timestamp": time.time()
        }
    except requests.exceptions.RequestException as e:
        raise HTTPException(400, f"Failed to fetch image: {e}")
    except Exception as e:
        raise HTTPException(500, f"Verification failed: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    print("=" * 70)
    print("🛡️  TrustNet AI - Forensic Media Verifier v3.0")
    print("=" * 70)
    print("🔬 Method: Deep Metadata & Forensic Analysis")
    print("📊 Detection Checks:")
    print("   ✓ EXIF metadata verification (camera, lens, timestamps)")
    print("   ✓ AI software signature detection (20+ generators)")
    print("   ✓ Resolution pattern analysis (AI-specific sizes)")
    print("   ✓ Texture & frequency forensics (Laplacian, gradients, FFT)")
    print("   ✓ Color profile validation")
    print("   ✓ Compression artifact analysis")
    print("   ✓ Edge definition analysis")
    print("   ✓ Noise pattern detection")
    print("=" * 70)
    print(f"🔑 Gemini validation: {'✅ Active' if gemini_available else '⚠️ Metadata-only'}")
    print("📍 Server: http://localhost:8000")
    print("📚 Docs: http://localhost:8000/docs")
    print("=" * 70)
    uvicorn.run(app, host="0.0.0.0", port=8001)

