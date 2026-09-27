"""
Graph Visualization Module for Bitcoin Wallet Risk Analyzer

Creates visual representations of transaction hops and money flow.
Each analyzed address gets a unique graph showing:
  - The target wallet (center)
  - Connected wallets at each hop level
  - Money flow direction and amount
  - Color-coded by risk (red=suspicious, green=clean, yellow=unknown)
"""

import matplotlib.pyplot as plt
import networkx as nx
import os
from datetime import datetime


def visualize_transaction_graph(graph, target_address, output_dir="graphs"):
    """
    Create a visual graph showing transaction hops and money flow.

    Args:
        graph: NetworkX DiGraph from blockchain_api.build_transaction_graph()
        target_address: The wallet address being analyzed
        output_dir: Directory to save the graph images

    Returns:
        Path to the saved graph image
    """
    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Create a subgraph with limited nodes for readability
    # Show target address + up to 20 most connected nodes
    nodes_to_show = [target_address]

    # Add nodes by hop level (including -1 for incoming funding sources)
    for hop in range(-1, 6):  # -1 to 5 hops
        hop_nodes = [n for n in graph.nodes()
                     if graph.nodes[n].get('hop', 0) == hop]
        nodes_to_show.extend(hop_nodes[:10])  # Limit per hop for clarity

    # Create subgraph
    subgraph = graph.subgraph(nodes_to_show).copy()

    if subgraph.number_of_nodes() == 0:
        print("  [Warning] No graph data to visualize")
        return None

    # Set up the plot
    plt.figure(figsize=(16, 12))
    plt.title(f"Transaction Flow Analysis\nTarget: {target_address[:20]}...",
              fontsize=16, fontweight='bold')

    # Create layout - shell layout groups nodes by hop distance
    hop_shells = []
    for hop in range(-1, 6):
        shell = [n for n in subgraph.nodes()
                 if subgraph.nodes[n].get('hop', 0) == hop]
        if shell:
            hop_shells.append(shell)

    if hop_shells and sum(len(s) for s in hop_shells) == subgraph.number_of_nodes():
        pos = nx.shell_layout(subgraph, nlist=hop_shells)
    else:
        pos = nx.spring_layout(subgraph, k=2, iterations=50)

    # Color nodes by hop level
    node_colors = []
    for node in subgraph.nodes():
        hop = subgraph.nodes[node].get('hop', 0)
        if node == target_address:
            node_colors.append('#FF4444')  # Red for target
        elif hop == -1:
            node_colors.append('#CC0066')  # Purple/crimson for incoming sources
        elif hop == 0:
            node_colors.append('#FF4444')
        elif hop == 1:
            node_colors.append('#FF8844')
        elif hop == 2:
            node_colors.append('#FFAA44')
        elif hop == 3:
            node_colors.append('#FFCC44')
        elif hop == 4:
            node_colors.append('#DDDD44')
        else:
            node_colors.append('#88CC44')

    # Node sizes based on degree (more connections = bigger node)
    node_sizes = []
    for node in subgraph.nodes():
        degree = subgraph.degree(node)
        size = 300 + (degree * 100)  # Base size + degree multiplier
        node_sizes.append(min(size, 2000))  # Cap at 2000

    # Draw nodes
    nx.draw_networkx_nodes(subgraph, pos,
                          node_color=node_colors,
                          node_size=node_sizes,
                          alpha=0.9,
                          edgecolors='black',
                          linewidths=2)

    # Draw edges with arrows
    nx.draw_networkx_edges(subgraph, pos,
                          edge_color='gray',
                          arrows=True,
                          arrowsize=15,
                          arrowstyle='->',
                          width=1.5,
                          alpha=0.6,
                          connectionstyle='arc3,rad=0.1')

    # Draw labels (shortened addresses)
    labels = {}
    for node in subgraph.nodes():
        if node == target_address:
            labels[node] = f"TARGET\n{node[:8]}..."
        else:
            labels[node] = f"{node[:8]}..."

    nx.draw_networkx_labels(subgraph, pos, labels,
                           font_size=8,
                           font_weight='bold',
                           font_color='white',
                           bbox=dict(boxstyle='round,pad=0.3',
                                   facecolor='black',
                                   alpha=0.7))

    # Add legend
    legend_elements = [
        plt.Line2D([0], [0], marker='o', color='w',
                   markerfacecolor='#CC0066', markersize=12,
                   label='Incoming Source (Hop -1)'),
        plt.Line2D([0], [0], marker='o', color='w',
                   markerfacecolor='#FF4444', markersize=12,
                   label='Target Wallet (Hop 0)'),
        plt.Line2D([0], [0], marker='o', color='w',
                   markerfacecolor='#FF8844', markersize=12,
                   label='Hop 1'),
        plt.Line2D([0], [0], marker='o', color='w',
                   markerfacecolor='#FFAA44', markersize=12,
                   label='Hop 2'),
        plt.Line2D([0], [0], marker='o', color='w',
                   markerfacecolor='#FFCC44', markersize=12,
                   label='Hop 3'),
        plt.Line2D([0], [0], marker='o', color='w',
                   markerfacecolor='#DDDD44', markersize=12,
                   label='Hop 4+'),
    ]
    plt.legend(handles=legend_elements, loc='upper left', fontsize=10)

    # Add statistics text
    all_hops = [subgraph.nodes[n].get('hop', 0) for n in subgraph.nodes()]
    max_hop = max(all_hops) if all_hops else 0
    stats_text = f"Graph Statistics:\n"
    stats_text += f"Total Addresses: {subgraph.number_of_nodes()}\n"
    stats_text += f"Total Connections: {subgraph.number_of_edges()}\n"
    stats_text += f"Max Hop Distance: {max_hop}"

    plt.text(0.02, 0.02, stats_text,
             transform=plt.gca().transAxes,
             fontsize=10,
             verticalalignment='bottom',
             bbox=dict(boxstyle='round', facecolor='white', alpha=0.8))

    plt.axis('off')
    plt.tight_layout()

    # Save the graph
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"graph_{target_address[:12]}_{timestamp}.png"
    filepath = os.path.join(output_dir, filename)

    plt.savefig(filepath, dpi=150, bbox_inches='tight', facecolor='white')
    print(f"\n  📊 Graph visualization saved: {filepath}")

    # Don't show the plot in non-interactive environments
    # plt.show()
    plt.close()

    return filepath


def create_hop_distribution_chart(graph, target_address, output_dir="graphs"):
    """
    Create a bar chart showing the distribution of addresses across hop levels.

    Args:
        graph: NetworkX DiGraph
        target_address: The wallet being analyzed
        output_dir: Directory to save the chart

    Returns:
        Path to the saved chart image
    """
    # Count addresses at each hop level
    hop_counts = {}
    for node in graph.nodes():
        hop = graph.nodes[node].get('hop', 0)
        hop_counts[hop] = hop_counts.get(hop, 0) + 1

    if not hop_counts:
        return None

    # Create the bar chart
    plt.figure(figsize=(10, 6))
    hops = sorted(hop_counts.keys())
    counts = [hop_counts[h] for h in hops]

    colors = ['#FF4444', '#FF8844', '#FFAA44', '#FFCC44', '#DDDD44', '#AADD44']
    bar_colors = [colors[min(h, len(colors)-1)] for h in hops]

    plt.bar(hops, counts, color=bar_colors, edgecolor='black', linewidth=1.5)
    plt.xlabel('Hop Distance from Target', fontsize=12, fontweight='bold')
    plt.ylabel('Number of Addresses', fontsize=12, fontweight='bold')
    plt.title(f'Address Distribution by Hop Level\nTarget: {target_address[:20]}...',
              fontsize=14, fontweight='bold')
    plt.xticks(hops)
    plt.grid(axis='y', alpha=0.3, linestyle='--')

    # Add value labels on bars
    for i, (hop, count) in enumerate(zip(hops, counts)):
        plt.text(hop, count + max(counts)*0.02, str(count),
                ha='center', va='bottom', fontweight='bold')

    plt.tight_layout()

    # Save the chart
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"hops_{target_address[:12]}_{timestamp}.png"
    filepath = os.path.join(output_dir, filename)

    plt.savefig(filepath, dpi=150, bbox_inches='tight', facecolor='white')
    print(f"  📊 Hop distribution chart saved: {filepath}")

    plt.close()

    return filepath


# Quick test
if __name__ == "__main__":
    # Create a test graph
    test_graph = nx.DiGraph()
    test_graph.add_edge("target_wallet", "wallet_1", weight=1.5)
    test_graph.add_edge("wallet_1", "wallet_2", weight=0.8)
    test_graph.add_edge("wallet_1", "wallet_3", weight=1.2)
    test_graph.add_edge("target_wallet", "wallet_4", weight=2.0)

    test_graph.nodes["target_wallet"]["hop"] = 0
    test_graph.nodes["wallet_1"]["hop"] = 1
    test_graph.nodes["wallet_2"]["hop"] = 2
    test_graph.nodes["wallet_3"]["hop"] = 2
    test_graph.nodes["wallet_4"]["hop"] = 1

    print("Testing graph visualization...")
    visualize_transaction_graph(test_graph, "target_wallet")
    create_hop_distribution_chart(test_graph, "target_wallet")
    print("✅ Test complete! Check the 'graphs' folder.")
