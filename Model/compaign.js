import mongoose from "mongoose";
const Schema = mongoose.Schema;

const campaignSchema = new Schema(
  {
    campaignName: {
      type: String,
      required: true
    },
    campaignDescription: {
      type: String,
      required: true
    },
    fundingGoal: {
      type: String,
      required: true
    },
    category: {
      type: String,
      required: true
    },
    milestoneTitle: {
      type: String,
      required: true
    },
    amountNeeded: {
      type: String,
      required: true
    },
    completionDate: {
      type: String,
      required: true
    },
    teamInformation: {
      type: String,
      required: true
    },
    expectedImpact: {
      type: String,
      required: true
    },
    risksAndChallenges: {
      type: String,
      required: true
    },
    creator: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    }
  },
  {
    timestamps: true,
  }
);

const Campaign = mongoose.model('Campaign', campaignSchema);

export default Campaign;